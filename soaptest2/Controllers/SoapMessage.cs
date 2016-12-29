using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Web;
using System.Xml;

namespace soaptest2.Controllers
{
    public class SoapMessage
    {
        public XmlElement Header { get; set; }

        public XmlElement Body { get; set; }

        public X509Certificate2 Certificate { get; set; }

        public XmlDocument GetXml(bool signed = false)
        {
            var doc = new XmlDocument {PreserveWhitespace = true};

            var soapEnvelopeXml = doc.CreateElement("s", "Envelope", "http://schemas.xmlsoap.org/soap/envelope/");
            soapEnvelopeXml.SetAttribute("xmlns:u", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");

            var soapHeaderXml = doc.CreateElement("s", "Header", "http://schemas.xmlsoap.org/soap/envelope/");
            if (Header != null)
            {
                var imported = doc.ImportNode(Header, true);
                soapHeaderXml.AppendChild(imported);
            }
            soapEnvelopeXml.AppendChild(soapHeaderXml);

            var soapBodyXml = doc.CreateElement("s", "Body", "http://schemas.xmlsoap.org/soap/envelope/");
            soapBodyXml.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_1");
            if (Body == null)
            {
                throw new Exception("Body is required.");
            }
            else
            {
                var imported = doc.ImportNode(Body, true);
                soapBodyXml.AppendChild(imported);
            }

            soapEnvelopeXml.AppendChild(soapBodyXml);
            doc.AppendChild(soapEnvelopeXml);

            if (signed)
            {
                SoapSigner signer = new SoapSigner();

                if (Certificate == null)
                {
                    throw new Exception("A X509 certificate is needed.");
                }

                XmlDocument tempDoc = new XmlDocument();
                tempDoc.PreserveWhitespace = true;
                tempDoc.LoadXml(doc.OuterXml);

                return signer.SignMessage(tempDoc, Certificate, SignAlgorithm.SHA1);
            }

            return doc;
        }

        public void ReadXml(XmlDocument document)
        {
            var ns = new XmlNamespaceManager(document.NameTable);
            ns.AddNamespace("s", "http://schemas.xmlsoap.org/soap/envelope/");

            if (document.DocumentElement != null)
            {
                Header = document.DocumentElement.SelectSingleNode("//s:Header", ns) as XmlElement;
                Body = document.DocumentElement.SelectSingleNode("//s:Body", ns) as XmlElement;
            }

            if (Body == null)
            {
                throw new Exception("No body found.");
            }
        }

        public static XmlDocument SignSoapBody(XmlDocument xmlDoc, X509Certificate2 cert)
        {
            var ns = new XmlNamespaceManager(xmlDoc.NameTable);
            ns.AddNamespace("soapenv", "http://schemas.xmlsoap.org/soap/envelope/");
            var body = xmlDoc.DocumentElement.SelectSingleNode(@"//soapenv:Body", ns) as XmlElement;
            if (body == null)
                throw new ApplicationException("No body tag found");
            body.SetAttribute("id", "Body");
            var signedXml = new SignedXml(xmlDoc);


            var keyInfo = new KeyInfo();
            signedXml.SigningKey = cert.PrivateKey;
            var keyInfoData = new KeyInfoX509Data();
            keyInfoData.AddIssuerSerial(cert.Issuer, cert.GetSerialNumberString());
            keyInfoData.AddCertificate(cert);
            keyInfo.AddClause(keyInfoData);
            signedXml.KeyInfo = keyInfo;


            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            var reference = new Reference();
            reference.Uri = "#Body";


            reference.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(reference);
            signedXml.ComputeSignature();


            var signedElement = signedXml.GetXml();
            signedElement.Prefix = "ds";
            //XmlElement soapSignature = xmlDoc.CreateElement("ds","Signature", "http://www.w3.org/2000/09/xmldsig#");


            //soapSignature.SetAttribute("MustUnderstand", "", "1");
            //soapSignature.AppendChild(signedElement);


            var soapHeader = xmlDoc.DocumentElement.SelectSingleNode("//soapenv:Header", ns) as XmlElement;
            soapHeader?.AppendChild(signedElement);
            return xmlDoc;
        }




        public X509Certificate2 GetCertificateBySubject(string subject, StoreName storeName, StoreLocation storeLocation)
        {
            var xstore = new X509Store(storeName, storeLocation);
            xstore.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            return xstore.Certificates.Cast<X509Certificate2>().FirstOrDefault(cert2 => "CN=" + subject == cert2.Subject);
        }
    }

}