using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;

namespace IrcDotNet.Test
{
    // Unit tests for SASL PLAIN authentication support.
    // These tests exercise the SASL logic in isolation without a real network
    // connection by using a testable subclass that captures outgoing raw messages.
    [TestFixture]
    public class SaslAuthenticationTests
    {
        // Testable subclass of IrcClient that captures outgoing raw messages and
        // exposes the protected SASL members required for testing.
        private class TestableSaslIrcClient : IrcClient
        {
            public readonly List<string> SentLines = new List<string>();

            public override bool IsConnected
            {
                get { return true; }
            }

            protected override void WriteMessage(string line, object token = null)
            {
                // Capture the raw outgoing line instead of writing to a network stream.
                SentLines.Add(line);
            }

            // Expose protected members for testing.
            public void InitializeState()
            {
                ResetState();
            }

            public void BeginConnect(IrcRegistrationInfo regInfo)
            {
                HandleClientConnected(regInfo);
            }

            public List<string> BuildPlainResponse(string username, string password)
            {
                return BuildSaslPlainResponse(username, password);
            }

            public IrcMessage MakeMessage(string command, params string[] parameters)
            {
                return new IrcMessage(this, null, command, parameters);
            }

            public void FeedCap(params string[] parameters)
            {
                ProcessMessageCap(MakeMessage("CAP", parameters));
            }

            public void FeedAuthenticate(string parameter)
            {
                ProcessMessageAuthenticate(MakeMessage("AUTHENTICATE", parameter));
            }

            public void FeedNumeric(string numeric, params string[] parameters)
            {
                switch (numeric)
                {
                    case "903":
                        ProcessMessageSaslSuccess(MakeMessage(numeric, parameters));
                        break;
                    case "904":
                        ProcessMessageSaslFail(MakeMessage(numeric, parameters));
                        break;
                    default:
                        throw new ArgumentException("Unsupported numeric for test helper.", nameof(numeric));
                }
            }
        }

        private static IrcUserRegistrationInfo CreateSaslRegInfo(string nick = "testnick",
            string saslUser = "sasluser", string saslPass = "saslpass")
        {
            return new IrcUserRegistrationInfo
            {
                NickName = nick,
                UserName = "testuser",
                RealName = "Test User",
                UserModes = new List<char>(),
                UseSasl = true,
                SaslUsername = saslUser,
                SaslPassword = saslPass
            };
        }

        [Test]
        public void BuildSaslPlainResponse_ProducesCorrectBase64()
        {
            var client = new TestableSaslIrcClient();
            client.InitializeState();

            var chunks = client.BuildPlainResponse("jilles", "sesame");

            // Expected: \0jilles\0sesame base64-encoded => AGppbGxlcwBzZXNhbWU=
            // (well-known example from the IRCv3 SASL specification).
            var expected = Convert.ToBase64String(Encoding.UTF8.GetBytes("\0jilles\0sesame"));
            Assert.That(chunks, Has.Count.EqualTo(1));
            Assert.That(chunks[0], Is.EqualTo(expected));
            Assert.That(chunks[0], Is.EqualTo("AGppbGxlcwBzZXNhbWU="));
        }

        [Test]
        public void BuildSaslPlainResponse_EmptyCredentials_SendsLonePlus()
        {
            var client = new TestableSaslIrcClient();
            client.InitializeState();

            var chunks = client.BuildPlainResponse("", "");

            // "\0\0" base64 is non-empty, so it should be a single chunk (not a lone "+").
            var expected = Convert.ToBase64String(Encoding.UTF8.GetBytes("\0\0"));
            Assert.That(chunks, Has.Count.EqualTo(1));
            Assert.That(chunks[0], Is.EqualTo(expected));
        }

        [Test]
        public void BuildSaslPlainResponse_ExactMultipleOf400_AppendsLonePlus()
        {
            var client = new TestableSaslIrcClient();
            client.InitializeState();

            // Choose a password whose encoded payload length is an exact multiple of 400.
            // base64 length is a multiple of 4; we need it to be a multiple of 400.
            // "\0u\0" is 3 bytes prefix; find a password producing total base64 len == 400.
            // 400 base64 chars => 300 input bytes. Prefix "\0" + user + "\0" = variable.
            // Use empty user: "\0" + "\0" + password => 2 + passwordBytes = 300 => 298 byte password.
            var password = new string('a', 298);
            var chunks = client.BuildPlainResponse("", password);

            var fullBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("\0\0" + password));
            Assert.That(fullBase64.Length % 400, Is.EqualTo(0));
            // Should produce one 400-char chunk plus a lone "+".
            Assert.That(chunks.Last(), Is.EqualTo("+"));
            Assert.That(chunks[0].Length, Is.EqualTo(400));
        }

        [Test]
        public void SaslFlow_RequestsSaslCapability_WhenServerSupportsIt()
        {
            var client = new TestableSaslIrcClient();
            client.InitializeState();
            client.BeginConnect(CreateSaslRegInfo());
            client.SentLines.Clear();

            // Server advertises capabilities including sasl.
            client.FeedCap("*", "LS", "multi-prefix sasl account-notify");

            Assert.That(client.SentLines.Any(l => l.Contains("CAP") && l.Contains("REQ") && l.Contains("sasl")),
                Is.True, "Expected a CAP REQ :sasl message.");
        }

        [Test]
        public void SaslFlow_RequestsSaslCapability_WhenAdvertisedWithMechanismValue()
        {
            var client = new TestableSaslIrcClient();
            client.InitializeState();
            client.BeginConnect(CreateSaslRegInfo());
            client.SentLines.Clear();

            // Server advertises sasl with a mechanism value (IRCv3.2 style).
            client.FeedCap("*", "LS", "multi-prefix sasl=PLAIN,EXTERNAL account-notify");

            Assert.That(client.SentLines.Any(l => l.Contains("CAP") && l.Contains("REQ") && l.Contains("sasl")),
                Is.True, "Expected a CAP REQ :sasl message when sasl is advertised with a value.");
        }

        [Test]
        public void SaslFlow_SendsAuthenticatePlain_OnCapAck()
        {
            var client = new TestableSaslIrcClient();
            client.InitializeState();
            client.BeginConnect(CreateSaslRegInfo());
            client.FeedCap("*", "LS", "sasl");
            client.SentLines.Clear();

            client.FeedCap("*", "ACK", "sasl");

            Assert.That(client.SentLines.Any(l => l.Contains("AUTHENTICATE") && l.Contains("PLAIN")),
                Is.True, "Expected an AUTHENTICATE PLAIN message.");
        }

        [Test]
        public void SaslFlow_SendsBase64Payload_OnAuthenticateChallenge()
        {
            var client = new TestableSaslIrcClient();
            client.InitializeState();
            client.BeginConnect(CreateSaslRegInfo(saslUser: "jilles", saslPass: "sesame"));
            client.FeedCap("*", "LS", "sasl");
            client.FeedCap("*", "ACK", "sasl");
            client.SentLines.Clear();

            // Server signals readiness with "AUTHENTICATE +".
            client.FeedAuthenticate("+");

            var expectedPayload = Convert.ToBase64String(Encoding.UTF8.GetBytes("\0jilles\0sesame"));
            Assert.That(client.SentLines.Any(l => l.Contains("AUTHENTICATE") && l.Contains(expectedPayload)),
                Is.True, "Expected the base64 SASL PLAIN payload to be sent.");
        }

        [Test]
        public void SaslFlow_SuccessRaisesEventAndCompletesRegistration()
        {
            var client = new TestableSaslIrcClient();
            client.InitializeState();
            client.BeginConnect(CreateSaslRegInfo());
            client.FeedCap("*", "LS", "sasl");
            client.FeedCap("*", "ACK", "sasl");
            client.FeedAuthenticate("+");
            client.SentLines.Clear();

            bool succeeded = false;
            bool connected = false;
            client.SaslAuthenticationSucceeded += (s, e) => succeeded = true;
            client.Connected += (s, e) => connected = true;

            client.FeedNumeric("903", "testnick", "SASL authentication successful");

            Assert.That(succeeded, Is.True, "Expected SaslAuthenticationSucceeded event to fire.");
            Assert.That(connected, Is.True, "Expected Connected event to fire after SASL success.");
            Assert.That(client.SentLines.Any(l => l.Contains("NICK")), Is.True, "Expected NICK to be sent.");
            Assert.That(client.SentLines.Any(l => l.Contains("USER")), Is.True, "Expected USER to be sent.");
            Assert.That(client.SentLines.Any(l => l.Contains("CAP") && l.Contains("END")), Is.True,
                "Expected CAP END to be sent.");
        }

        [Test]
        public void SaslFlow_FailureRaisesEventAndContinuesUnauthenticated()
        {
            var client = new TestableSaslIrcClient();
            client.InitializeState();
            client.BeginConnect(CreateSaslRegInfo());
            client.FeedCap("*", "LS", "sasl");
            client.FeedCap("*", "ACK", "sasl");
            client.FeedAuthenticate("+");
            client.SentLines.Clear();

            SaslAuthenticationFailedEventArgs failureArgs = null;
            bool connected = false;
            client.SaslAuthenticationFailed += (s, e) => failureArgs = e;
            client.Connected += (s, e) => connected = true;

            client.FeedNumeric("904", "testnick", "SASL authentication failed");

            Assert.That(failureArgs, Is.Not.Null, "Expected SaslAuthenticationFailed event to fire.");
            Assert.That(failureArgs.Mechanism, Is.EqualTo("PLAIN"));
            Assert.That(connected, Is.True, "Expected registration to continue after SASL failure.");
            Assert.That(client.SentLines.Any(l => l.Contains("CAP") && l.Contains("END")), Is.True,
                "Expected CAP END to be sent even after failure.");
        }

        [Test]
        public void SaslFlow_ServerWithoutSasl_ContinuesUnauthenticated()
        {
            var client = new TestableSaslIrcClient();
            client.InitializeState();
            client.BeginConnect(CreateSaslRegInfo());
            client.SentLines.Clear();

            SaslAuthenticationFailedEventArgs failureArgs = null;
            client.SaslAuthenticationFailed += (s, e) => failureArgs = e;

            // Server advertises no SASL support.
            client.FeedCap("*", "LS", "multi-prefix account-notify");

            Assert.That(failureArgs, Is.Not.Null, "Expected failure event when server lacks SASL.");
            Assert.That(client.SentLines.Any(l => l.Contains("CAP") && l.Contains("END")), Is.True,
                "Expected CAP END when SASL is unsupported.");
        }

        [Test]
        public void NonSaslRegistration_DoesNotStartSaslExchange()
        {
            var client = new TestableSaslIrcClient();
            client.InitializeState();

            var regInfo = new IrcUserRegistrationInfo
            {
                NickName = "plainnick",
                UserName = "plainuser",
                RealName = "Plain User",
                UserModes = new List<char>(),
                UseSasl = false
            };

            bool connected = false;
            client.Connected += (s, e) => connected = true;
            client.BeginConnect(regInfo);

            // Non-SASL path should send NICK/USER immediately and raise Connected.
            Assert.That(connected, Is.True);
            Assert.That(client.SentLines.Any(l => l.Contains("NICK")), Is.True);
            Assert.That(client.SentLines.Any(l => l.Contains("USER")), Is.True);
            Assert.That(client.SentLines.Any(l => l.Contains("AUTHENTICATE")), Is.False,
                "Non-SASL registration must not send AUTHENTICATE.");
        }
    }
}
