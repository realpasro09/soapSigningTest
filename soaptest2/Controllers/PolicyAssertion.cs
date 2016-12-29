using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Microsoft.Web.Services3;
using Microsoft.Web.Services3.Design;
using Microsoft.Web.Services3.Security;
using Microsoft.Web.Services3.Security.Tokens;

namespace soaptest2.Controllers
{
    public class CustomSecurityAssertion : SecurityPolicyAssertion
    {
        public TokenProvider<X509SecurityToken> ServiceX509TokenProviderValue;
        public TokenProvider<X509SecurityToken> ClientX509TokenProviderValue;

        public TokenProvider<X509SecurityToken> ClientX509TokenProvider
        {
            get
            {
                return ClientX509TokenProviderValue;
            }
            set
            {
                ClientX509TokenProviderValue = value;
            }
        }

        public TokenProvider<X509SecurityToken> ServiceX509TokenProvider
        {
            get
            {
                return ServiceX509TokenProviderValue;
            }
            set
            {
                ServiceX509TokenProviderValue = value;
            }
        }


        public override SoapFilter CreateClientOutputFilter(FilterCreationContext context)
        {
            return new CustomSecurityClientOutputFilter(this);
        }

        public override SoapFilter CreateClientInputFilter(FilterCreationContext context)
        {
            return new CustomSecurityClientInputFilter(this);
        }

        public override SoapFilter CreateServiceInputFilter(FilterCreationContext context)
        {
            return new CustomSecurityServerInputFilter(this);
        }

        public override SoapFilter CreateServiceOutputFilter(FilterCreationContext context)
        {
            return new CustomSecurityServerOutputFilter(this);
        }


        public override void ReadXml(System.Xml.XmlReader reader, IDictionary<string, Type> extensions)
        {
            if (reader == null)
                throw new ArgumentNullException("reader");
            if (extensions == null)
                throw new ArgumentNullException("extensions");

            var isEmpty = reader.IsEmptyElement;
            base.ReadAttributes(reader);
            reader.ReadStartElement("CustomSecurityAssertion");

            if (isEmpty) return;
            if (reader.MoveToContent() == XmlNodeType.Element && reader.Name == "clientToken")
            {
                reader.ReadStartElement();
                reader.MoveToContent();
                // Get the registed security token provider for X.509 certificate security credentials. 
                var type = extensions[reader.Name];
                var instance = Activator.CreateInstance(type);

                if (instance == null)
                    throw new InvalidOperationException(String.Format(System.Globalization.CultureInfo.CurrentCulture, "Unable to instantiate policy extension of type {0}.", type.AssemblyQualifiedName));

                var clientProvider = instance as TokenProvider<X509SecurityToken>;

                // Read the child elements that provide the details about the client's X.509 certificate. 
                if (clientProvider != null)
                {
                    clientProvider.ReadXml(reader, extensions);
                    ClientX509TokenProvider = clientProvider;
                }
                reader.ReadEndElement();
            }
            if (reader.MoveToContent() == XmlNodeType.Element && reader.Name == "serviceToken")
            {
                reader.ReadStartElement();
                reader.MoveToContent();

                // Get the registed security token provider for X.509 certificate security credentials. 
                var type = extensions[reader.Name];
                var instance = Activator.CreateInstance(type);

                if (instance == null)
                    throw new InvalidOperationException(String.Format(System.Globalization.CultureInfo.CurrentCulture, "Unable to instantiate policy extension of type {0}.", type.AssemblyQualifiedName));

                var serviceProvider = instance as TokenProvider<X509SecurityToken>;
                // Read the child elements that provide the details about the Web service's X.509 certificate.
                if (serviceProvider != null)
                {
                    serviceProvider.ReadXml(reader, extensions);
                    ServiceX509TokenProvider = serviceProvider;
                }
                reader.ReadEndElement();
            }
            ReadElements(reader, extensions);
            reader.ReadEndElement();
        }
        public override IEnumerable<KeyValuePair<string, Type>> GetExtensions()
        {
            // Add the CustomSecurityAssertion custom policy assertion to the list of registered
            // policy extensions.
            var extensions = new List<KeyValuePair<string, Type>>
            {
                new KeyValuePair<string, Type>("CustomSecurityAssertion", this.GetType())
            };
            if (ServiceX509TokenProviderValue != null)
            {
                // Add any policy extensions that read child elements of the <serviceToken> element
                // to the list of registered policy extensions.
                var innerExtensions = ServiceX509TokenProviderValue.GetExtensions();
                if (innerExtensions != null)
                {
                    extensions.AddRange(innerExtensions);
                }
            }
            if (ClientX509TokenProviderValue == null) return extensions;
            {
                // Add any policy extensions that read child elements of the <clientToken> element
                // to the list of registered policy extensions.
                var innerExtensions = ClientX509TokenProviderValue.GetExtensions();
                if (innerExtensions == null) return extensions;
                extensions.AddRange(innerExtensions);
            }
            return extensions;
        }
        // </snippet16

    }

    public class RequestState
    {
        public RequestState(SecurityToken cToken, SecurityToken sToken)
        {
            ClientToken = cToken;
            ServerToken = sToken;
        }

        public SecurityToken ClientToken { get; }

        public SecurityToken ServerToken { get; }
    }

    public class CustomSecurityServerInputFilter : ReceiveSecurityFilter
    {
        private readonly CustomSecurityAssertion _parentAssertion;

        public CustomSecurityServerInputFilter(CustomSecurityAssertion parentAssertion)
            : base(parentAssertion.ServiceActor, false)
        {
            _parentAssertion = parentAssertion;
        }
        public override void ValidateMessageSecurity(SoapEnvelope envelope, Security security)
        {
            SecurityToken clientToken = null;
            SecurityToken serverToken = null;

            // Ensure incoming SOAP messages are signed and encrypted.
            foreach (ISecurityElement elem in security.Elements)
            {
                if (elem is MessageSignature)
                {
                    var sig = (MessageSignature)elem;
                    clientToken = sig.SigningToken;
                }

                if (elem is EncryptedData)
                {
                    EncryptedData enc = (EncryptedData)elem;
                    serverToken = enc.SecurityToken;
                }
            }

            if (clientToken == null || serverToken == null)
                throw new Exception("Incoming message did not meet security requirements");

            RequestState state = new RequestState(clientToken, serverToken);

            envelope.Context.OperationState.Set(state);
        }
    }

    class CustomSecurityServerOutputFilter : SendSecurityFilter
    {

        public CustomSecurityServerOutputFilter(CustomSecurityAssertion parentAssertion)
            : base(parentAssertion.ServiceActor, false)
        {
        }

        public override void SecureMessage(SoapEnvelope envelope, Security security)
        {
            RequestState state = envelope.Context.OperationState.Get<RequestState>();

            // Sign the message with the Web service's security token.
            security.Tokens.Add(state.ServerToken);
            security.Elements.Add(new MessageSignature(state.ServerToken));

            // Encrypt the message with the client's security token.
            security.Elements.Add(new EncryptedData(state.ClientToken));
        }
    }

    internal class CustomSecurityClientInputFilter : ReceiveSecurityFilter
    {
        public CustomSecurityClientInputFilter(SecurityPolicyAssertion parentAssertion)
            : base(parentAssertion.ServiceActor, true)
        {

        }

        public override void ValidateMessageSecurity(SoapEnvelope envelope, Security security)
        {
            var isSigned = false;
            const SignatureOptions expectedOptions = SignatureOptions.IncludeTimestamp |
                                                     SignatureOptions.IncludeSoapBody |
                                                     SignatureOptions.IncludeTo |
                                                     SignatureOptions.IncludeAction |
                                                     SignatureOptions.IncludeMessageId;
            foreach (ISecurityElement element in security.Elements)
            {
                // The given context contains a Signature element.
                var sig = element as MessageSignature;
                if ((sig?.SignatureOptions & expectedOptions) != expectedOptions) continue;
                // The SOAP body and the WS-Addressing headers are signed.
                if (sig.SigningToken is X509SecurityToken)
                    // The SOAP message is signed by a X509SecurityToken.
                    isSigned = true;
            }
            if (!isSigned)
                throw new SecurityFault("Message did not meet security requirements.");
        }
    }

    public class CustomSecurityClientOutputFilter : SendSecurityFilter
    {
        public readonly SecurityToken ClientToken;
        public readonly SecurityToken ServerToken;

        public CustomSecurityClientOutputFilter(SecurityPolicyAssertion parentAssertion)
            : base(parentAssertion.ServiceActor, true)
        {
            ClientToken = X509TokenProvider.CreateToken(StoreLocation.CurrentUser, StoreName.My, "CN=WSE2QuickStartClient");
            ServerToken = X509TokenProvider.CreateToken(StoreLocation.LocalMachine, StoreName.My, "CN=WSE2QuickStartServer");
        }

        public override void SecureMessage(SoapEnvelope envelope, Security security)
        {
            //security.Tokens.Add(ClientToken);
            //security.Elements.Add(new MessageSignature(ClientToken));
            //security.Elements.Add(new EncryptedData(ServerToken));
            //security.Elements.Add(new EncryptedData(ServerToken, "#" + ClientToken.Id));
            //var state = new RequestState(ClientToken, ServerToken);
            //envelope.Context.OperationState.Set(state);
            var signatureToken = GetSecurityToken("CN=WSE2QuickStartClient");
            if (signatureToken == null)
            {
                throw new SecurityFault("Message Requirements could not be satisfied.");
            }
            
            security.Tokens.Add(signatureToken);
            var sig = new MessageSignature(signatureToken);

            security.Elements.Add(sig);
        }

        public X509SecurityToken GetSecurityToken(string subjectName)
        {
            X509SecurityToken securityToken = null;
            var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            try
            {
                var certs = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, subjectName, false);

                if (certs.Count == 1)
                {
                    var cert = certs[0];
                    securityToken = new X509SecurityToken(cert);
                }
                else
                    securityToken = null;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
            finally
            {
                store.Close();
            }
            return securityToken;
        }
    }
}