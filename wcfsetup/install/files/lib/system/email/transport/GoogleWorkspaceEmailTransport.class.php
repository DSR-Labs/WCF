<?php

namespace wcf\system\email\transport;

use GuzzleHttp\Psr7\Request;
use InvalidArgumentException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use wcf\system\email\Email;
use wcf\system\email\Mailbox;
use wcf\system\email\transport\exception\PermanentFailure;
use wcf\system\email\transport\exception\TransientFailure;
use wcf\system\exception\SystemException;
use wcf\system\io\HttpFactory;
use wcf\system\io\RemoteFile;
use wcf\system\registry\RegistryHandler;
use wcf\system\WCF;
use wcf\util\StringUtil;

/**
 * GoogleWorkspaceEmailTransport is an implementation of an email transport
 * which sends emails via SMTP (RFC 5321, 3207 and 4954) and supports XOAUTH2.
 *
 * @author      Alexander Ebert
 * @copyright   2001-2025 WoltLab GmbH
 * @license     GNU Lesser General Public License <http://opensource.org/licenses/lgpl-license.php>
 * @since       6.2
 */
final class GoogleWorkspaceEmailTransport implements IStatusReportingEmailTransport
{
    /**
     * SMTP connection
     */
    private ?RemoteFile $connection = null;

    /**
     * host of the smtp server to use
     */
    private readonly string $host;

    /**
     * port to use
     */
    private readonly int $port;

    private readonly string $clientEmail;
    private readonly string $privateKey;
    private readonly string $privateKeyId;
    private readonly string $tokenUri;

    /**
     * STARTTLS encryption level
     */
    private readonly string $starttls;

    /**
     * last value written to the server
     */
    private string $lastWrite = '';

    /**
     * ESMTP features advertised by the server
     * @var string[]
     */
    private array $features = [];

    /**
     * if this property is an instance of \Exception email delivery will be locked
     * and the \Exception will be thrown when attempting to deliver() an email
     */
    private ?\Exception $locked = null;

    /**
     * @throws \InvalidArgumentException
     */
    public function __construct(
        #[\SensitiveParameter]
        $json = \MAIL_GOOGLE_WORKSPACE_JSON,
    ) {
        $this->host = 'smtp.gmail.com';
        $this->port = 587;

        try {
            $parsed = \json_decode($json, true, flags: \JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new InvalidArgumentException("The provided JSON configuration for Google Workspace is invalid.");
        }

        $this->clientEmail = $parsed['client_email'];
        $this->privateKey = $parsed['private_key'];
        $this->privateKeyId = $parsed['private_key_id'];
        $this->tokenUri = $parsed['token_uri'];
    }

    /**
     * @inheritDoc
     */
    public function __destruct()
    {
        $this->disconnect();
    }

    /**
     * Tests the connection by establishing a connection and optionally
     * providing user credentials. Returns the error message or an empty
     * string on success.
     */
    public function testConnection(): string
    {
        try {
            $this->connect(10);
            $this->auth();
        } catch (SystemException $e) {
            if (\strpos($e->getMessage(), 'Can not connect to') === 0) {
                return WCF::getLanguage()->get('wcf.acp.email.smtp.test.error.hostUnknown');
            }

            return $e->getMessage();
        } catch (PermanentFailure $e) {
            if (\strpos($e->getMessage(), 'Remote SMTP server does not support EHLO') === 0) {
                return WCF::getLanguage()->get('wcf.acp.email.smtp.test.error.notTlsSupport');
            } elseif (\strpos($e->getMessage(), 'Remote SMTP server does not advertise STARTTLS') === 0) {
                return WCF::getLanguage()->get('wcf.acp.email.smtp.test.error.notTlsSupport');
            } elseif (\strpos($e->getMessage(), "Remote SMTP server reported permanent error code: 535 (") === 0) {
                return WCF::getLanguage()->get('wcf.acp.email.smtp.test.error.badAuth');
            }

            return $e->getMessage();
        } catch (TransientFailure $e) {
            if (\strpos($e->getMessage(), 'Enabling TLS failed') === 0) {
                return WCF::getLanguage()->get('wcf.acp.email.smtp.test.error.tlsFailed');
            }

            return $e->getMessage();
        }

        $this->disconnect();

        return '';
    }

    /**
     * Reads a server reply and validates it against the given expected status codes.
     * Returns a tuple [ status code, reply text ].
     *
     * @param int[] $expectedCodes
     * @return array{0: ?int, 1: string}
     * @throws PermanentFailure
     * @throws TransientFailure
     */
    protected function read(array $expectedCodes): array
    {
        $truncateReply = static function ($reply) {
            return StringUtil::truncate(
                \preg_replace('/[\x00-\x1F\x80-\xFF]/', '.', $reply),
                //250,
                9999,
                StringUtil::HELLIP,
                true
            );
        };

        $code = null;
        $reply = '';
        do {
            $start = \microtime(true);
            $data = $this->connection->gets();
            $end = \microtime(true);
            $time = $end - $start;

            if (\preg_match('/^(\d{3})([- ])(.*)$/', $data, $matches)) {
                if ($code === null) {
                    $code = \intval($matches[1]);

                    if (!\in_array($code, $expectedCodes)) {
                        // 4xx is a transient failure
                        if (400 <= $code && $code < 500) {
                            throw new TransientFailure(\sprintf(
                                "Remote SMTP server reported transient error code %d (%s) in reply to '%s' (%.3fs).",
                                $code,
                                $truncateReply($matches[3]),
                                $this->lastWrite,
                                $time
                            ));
                        }

                        // 5xx is a permanent failure
                        if (500 <= $code && $code < 600) {
                            throw new PermanentFailure(\sprintf(
                                "Remote SMTP server reported permanent error code %d (%s) in reply to '%s' (%.3fs).",
                                $code,
                                $truncateReply($matches[3]),
                                $this->lastWrite,
                                $time
                            ));
                        }

                        throw new TransientFailure(\sprintf(
                            "Remote SMTP server reported not expected code %d (%s) in reply to '%s' (%.3fs).",
                            $code,
                            $truncateReply($matches[3]),
                            $this->lastWrite,
                            $time
                        ));
                    }
                }

                if ($code == $matches[1]) {
                    $reply .= \trim($matches[3]) . "\r\n";

                    // no more continuation lines
                    if ($matches[2] === ' ') {
                        break;
                    }
                } else {
                    throw new TransientFailure(\sprintf(
                        "Unexpected reply '%s' from SMTP server. Code does not match previous codes %d from multiline answer (%.3fs).",
                        $data,
                        $code,
                        $time
                    ));
                }
            } else {
                if ($this->connection->eof()) {
                    throw new TransientFailure(\sprintf(
                        "Unexpected EOF / connection close from SMTP server (%.3fs).",
                        $time
                    ));
                }
                if ($data === false) {
                    // fgets returning false without feof returning true indicates that
                    // the read timeout struck. The connection will still be usable, though.
                    //
                    // We must tear down the connection to avoid a desync when the SMTP server
                    // sends the response to whatever command is currently waiting for the
                    // response when we already attempt to deliver a new mail:
                    //
                    // RCPT TO:<foo@example.com>
                    // -> timeout strikes
                    // RSET
                    // -> SMTP server belatedly responds to the RCPT TO, the response will
                    //    be interpreted as the response to the RSET.
                    // MAIL FROM:<bar@example.com>
                    // -> SMTP server responds to the RSET
                    $this->disconnect();

                    throw new TransientFailure(\sprintf(
                        "Failed to read from SMTP server (%.3fs).",
                        $time
                    ));
                }

                throw new TransientFailure(\sprintf(
                    "Unexpected reply '%s' from SMTP server (%.3fs).",
                    $data,
                    $time
                ));
            }
        } while (true);

        return [$code, $reply];
    }

    /**
     * Writes the given line to the server.
     */
    private function write(string $data): void
    {
        $this->lastWrite = $data;
        $this->connection->write($data . "\r\n");
    }

    /**
     * Connects to the server and enables STARTTLS if available. Bails
     * out if STARTTLS is not available and connection is set to 'encrypt'.
     *
     * @throws PermanentFailure
     */
    private function connect(?int $overrideTimeout = null): void
    {
        if ($overrideTimeout === null) {
            $this->connection = new RemoteFile($this->host, $this->port);
        } else {
            $this->connection = new RemoteFile($this->host, $this->port, $overrideTimeout);
        }
        $this->lastWrite = '*connect*';

        $this->read([220]);

        $this->write('EHLO ' . Email::getHost());
        $this->features = \array_map(
            'strtolower',
            \explode("\n", StringUtil::unifyNewlines($this->read([250])[1]))
        );

        $this->starttls();

        $this->write('EHLO ' . Email::getHost());
        $this->features = \array_map(
            'strtolower',
            \explode("\n", StringUtil::unifyNewlines($this->read([250])[1]))
        );
    }

    /**
     * Enables STARTTLS on the connection.
     *
     * @throws TransientFailure
     */
    private function starttls(): void
    {
        $this->write("STARTTLS");
        $this->read([220]);

        try {
            if (!$this->connection->setTLS(true)) {
                throw new TransientFailure('Enabling TLS failed');
            }
        } catch (SystemException $e) {
            throw new TransientFailure('Enabling TLS failed', 0, $e);
        }
    }

    /**
     * Performs SASL authentication using the credentials provided in the
     * constructor. Supported mechanisms are LOGIN and PLAIN.
     */
    private function auth(): void
    {
        if (!$this->privateKey) {
            return;
        }

        $supportsOauth2 = \array_any($this->features, static function (string $feature) {
            $parameters = \explode(" ", $feature);

            if ($parameters[0] !== 'auth') {
                return false;
            }

            return \in_array('xoauth2', $parameters);
        });
        if (!$supportsOauth2) {
            throw new TransientFailure("Remote SMTP server does not support XOAUTH2.", 0,);
        }

        $authToken = $this->getAccessToken();

        $this->write("AUTH XOAUTH2");
        $this->lastWrite = "AUTH XOAUTH2";
        $this->read([334]);

        $authString = \base64_encode(
            \sprintf(
                "user=%s\1auth=Bearer %s\1\1",
                $this->clientEmail,
                $authToken,
            )
        );

        $this->write($authString);
        $this->lastWrite = '*redacted*';
        $this->read([235]);

        /*
        $maximumSmtpLength = 998;
        for ($offset = 0, $length = \strlen($authString); $offset < $length; $offset += $maximumSmtpLength) {
            $segment = \substr($authString, $offset, $maximumSmtpLength);
            $expectedResponseCode = 235;
            if (\strlen($segment) === $maximumSmtpLength) {
                $segment = "{$segment}\r\n";
                $expectedResponseCode = 334;
            }

            $this->write($segment);
            $this->lastWrite = '*redacted*';
            $this->read([$expectedResponseCode]);
        }
            */
    }

    /**
     * Cleanly closes the connection to the server.
     */
    private function disconnect(): void
    {
        if ($this->connection) {
            try {
                $this->write("QUIT");
                $this->connection->close();
            } catch (SystemException $e) {
                // quit failed, don't care about it
            } finally {
                $this->connection = null;
            }
        }
    }

    /**
     * Delivers the given email using SMTP.
     *
     * @throws \Exception
     * @throws PermanentFailure
     */
    public function deliver(Email $email, Mailbox $envelopeFrom, Mailbox $envelopeTo): string
    {
        // delivery is locked
        if ($this->locked instanceof \Exception) {
            throw $this->locked;
        }

        // Fetch the payload early. This avoids starting an SMTP transaction if
        // generating the email contents ultimately does not succeed.
        $payload = $email->getEmail();

        if (!$this->connection || $this->connection->eof()) {
            try {
                $this->connect();
                $this->auth();
            } catch (PermanentFailure $e) {
                // lock delivery on permanent failure to avoid spamming the SMTP server
                $this->locked = $e;
                $this->disconnect();

                throw $e;
            } catch (\Exception $e) {
                $this->disconnect();

                throw $e;
            }
        }

        try {
            $this->write('RSET');
            $this->read([250]);
        } catch (\Exception $e) {
            // If the RSET command failed, then this most likely means that the state
            // of the SMTP connection desynced between client and server.
            //
            // This can happen if an LF is inserted into the MAIL FROM or RCPT TO
            // address. This will push the trailing `>` into a new line, which itself
            // will be terminated by CRLF, thus resulting in it interpreted by a separate
            // command which itself will then be interpreted as the response to whatever
            // the SMTP transport sends next (most likely the RSET).
            //
            // If such a desync is detected, we must tear down the SMTP connection to
            // revert back to a known safe state within a fresh connection.
            $this->disconnect();

            // We must wrap any existing exception, because it most likely is a bogus PermanentFailure with
            // cause '5.5.2 Error: command not recognized'. If we would emit the PermanentFailure, then we
            // would drop the email, even though the email itself is not at fault.
            throw new TransientFailure('Failed to RSET the SMTP connection.', 0, $e);
        }

        $this->write('MAIL FROM:<' . $envelopeFrom->getAddress() . '>');
        $this->read([250]);
        $this->write('RCPT TO:<' . $envelopeTo->getAddress() . '>');
        $this->read([250, 251]);
        $this->write('DATA');
        $this->read([354]);
        $this->connection->write(\implode("\r\n", \array_map(static function ($item) {
            // 4.5.2 Transparency
            // o  Before sending a line of mail text, the SMTP client checks the
            //    first character of the line.  If it is a period, one additional
            //    period is inserted at the beginning of the line.
            if (\str_starts_with($item, '.')) {
                return '.' . $item;
            }

            return $item;
        }, \explode("\r\n", $payload))) . "\r\n");
        $this->write(".");
        [, $message] = $this->read([250]);

        return $message;
    }

    private function getAccessToken(): string
    {
        $registryKey = 'googleWorkspaceAuthToken';
        $value = RegistryHandler::getInstance()->get('com.woltlab.wcf', $registryKey);
        if ($value !== null) {
            // TODO: Handle JsonException
            $data = \json_decode($value, true, flags: \JSON_THROW_ON_ERROR);
            if ($data['expires'] >= \TIME_NOW + 300) {
                return $data['accessToken'];
            }
        }

        $claims = [
            'iss' => $this->clientEmail,
            'scope' => 'https://www.googleapis.com/auth/gmail.send',
            'aud' => $this->tokenUri,
            // 5 minutes less than 60 minutes to account for any clock differences
            'exp' => \TIME_NOW + 3300,
            'iat' => \TIME_NOW,
        ];
        $payload = \json_encode($claims, \JSON_THROW_ON_ERROR);

        $jwk = JWKFactory::createFromKey($this->privateKey);

        $algorithmManager = new AlgorithmManager([new RS256()]);
        $jwsBuilder = new JWSBuilder($algorithmManager);
        $jws = $jwsBuilder
            ->create()
            ->withPayload($payload)
            ->addSignature(
                $jwk,
                [
                    'alg' => 'RS256',
                    'kid' => $this->privateKeyId,
                ]
            )
            ->build();

        $token = (new CompactSerializer())->serialize($jws);

        $httpClient = HttpFactory::makeClientWithTimeout(5);

        $request = new Request(
            'POST',
            $this->tokenUri,
            [
                'Accept' => 'application/json',
                'Content-Type' => 'application/x-www-form-urlencoded',
            ],
            \http_build_query(
                [
                    'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                    'assertion' => $token,
                ],
                '',
                '&',
                \PHP_QUERY_RFC1738
            )
        );

        // TODO: Handle errors
        $response = $httpClient->send($request);

        // TODO: Handle JsonException
        $parsed = \json_decode((string)$response->getBody(), true, flags: \JSON_THROW_ON_ERROR);

        $accessToken = $parsed['access_token'];

        RegistryHandler::getInstance()->set(
            'com.woltlab.wcf',
            $registryKey,
            \json_encode([
                'expires' => \time() + 3600,
                'accessToken' => $accessToken,
            ], \JSON_THROW_ON_ERROR)
        );

        return $accessToken;
    }
}
