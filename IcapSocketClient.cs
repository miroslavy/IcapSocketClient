using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace IcapSocket
{
    public class IcapSocketClient : IDisposable
    {
        private readonly String serverHost;
        private readonly int serverPort;

        private Socket sender;
        
        private const String VERSION = "1.0";
        private const String USERAGENT = "IT-Kartellet ICAP Client/1.1";
        private const String ICAPTERMINATOR = "\r\n\r\n";
        private const String HTTPTERMINATOR = "0\r\n\r\n";

        private const int cancelationTokenDelaySeconds = 60;

        private int stdPreviewSize;
        private const int stdRecieveLength = 8192;
        private const int stdSendLength = 8192;

        private byte[] buffer = new byte[8192];
        private String tempString;


        //private CancellationTokenSource tokenSource;
        //private CancellationToken ct;


        public IcapSocket()
        {
            try {
                // ICAP enabled service endpoint
                this.serverHost = ConfigurationManager.AppSettings["AntiVirusIcap.Host"].ToString();              
                this.serverPort = int.Parse(ConfigurationManager.AppSettings["AntiVirusIcap.Port"].ToString());   

                //Initialize connection
                IPAddress ipAddress;
                if (!IPAddress.TryParse(serverHost, out ipAddress))
                {
                    IPHostEntry hostEntry = Dns.GetHostEntry(this.serverHost);
                    if (hostEntry.AddressList.Length > 0)
                    {
                        ipAddress = hostEntry.AddressList[0];
                    }
                    else {
                        throw new ICAPException("AntiVirusIcap.Host is either invalid IP or invalid/unreachable hostname!");
                    }
                }
                IPEndPoint remoteEP = new IPEndPoint(ipAddress, serverPort);

                // Create a TCP/IP  socket.
                sender = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                sender.Connect(remoteEP);


                String parseMe = GetOptions();
                Dictionary<string, string> responseMap = ParseHeader(parseMe);

                responseMap.TryGetValue("StatusCode", out tempString);
                if (tempString != null)
                {
                    int status = Convert.ToInt16(tempString);

                    switch (status)
                    {
                        case 200:
                            responseMap.TryGetValue("Preview", out tempString);
                            if (tempString != null)
                            {
                                stdPreviewSize = Convert.ToInt16(tempString);
                            }; break;
                        default: throw new ICAPException("Could not get preview size from server");
                    }
                }
                else
                {
                    throw new ICAPException("Could not get options from server");
                }
            }
            catch (ConfigurationException)
            {
                throw new ICAPException("Could not read AntiVirusIcap configuration values from web.config");
            }
            catch (Exception)
            {
                throw new ICAPException("Could not initialize IcapRequest object.");
            }


        }

        public bool IsVirusFree(string fullFileName, byte[] fileContent)
        {
            using (MemoryStream fileStream = new MemoryStream(fileContent))
            {
                int fileSize = (int)fileStream.Length;
                int previewSize = stdPreviewSize;
                if (fileSize < stdPreviewSize)
                {
                    previewSize = fileSize;
                }

                //First part of header
                string requestBody = BuildRequestHeaders(fullFileName, fileContent.Length, previewSize);

                sender.Send(Encoding.ASCII.GetBytes(requestBody.ToString()));

                //Sending preview or, if smaller than previewSize, the whole file.
                byte[] chunk = new byte[previewSize];

                fileStream.Read(chunk, 0, previewSize);
                sender.Send(chunk);
                sender.Send(Encoding.ASCII.GetBytes("\r\n"));
                if (fileSize <= previewSize)
                {
                    sender.Send(Encoding.ASCII.GetBytes("0; ieof\r\n\r\n"));
                }
                else if (previewSize != 0)
                {
                    sender.Send(Encoding.ASCII.GetBytes("0\r\n\r\n"));
                }


                // Parse the response! It might not be "100 continue".
                // if fileSize<previewSize, then the stream waiting is actually the allowed/disallowed signal
                // otherwise it is a "go" for the rest of the file.
                Dictionary<String, String> responseMap = new Dictionary<string, string>();
                int status;

                if (fileSize > previewSize)
                {
                    //TODO: add timeout. It will hang if no response is recieved
                    String parseMe = GetHeader(ICAPTERMINATOR);
                    responseMap = ParseHeader(parseMe);

                    responseMap.TryGetValue("StatusCode", out tempString);
                    if (tempString != null)
                    {
                        status = Convert.ToInt16(tempString);

                        switch (status)
                        {
                            case 100: break; //Continue transfer
                            case 200: return false;
                            case 204: return true;
                            case 404: throw new ICAPException("404: ICAP Service not found");
                            default: throw new ICAPException("Server returned unknown status code:" + status);
                        }
                    }
                }

                //Sending remaining part of file
                if (fileSize > previewSize)
                {
                    int offset = previewSize;
                    int n;
                    int chunkLen = fileSize - previewSize;
                    byte[] buffer = new byte[chunkLen];
                    while ((n = fileStream.Read(buffer, 0, chunkLen)) > 0)
                    {
                        offset += n;  // offset for next reading
                        sender.Send(Encoding.ASCII.GetBytes(buffer.Length.ToString("X") + "\r\n"));
                        sender.Send(buffer);
                        sender.Send(Encoding.ASCII.GetBytes("\r\n"));
                    }
                    //Closing file transfer.
                    sender.Send(Encoding.ASCII.GetBytes("0\r\n\r\n"));
                }

                //fileStream.Close();
                sender.Send(Encoding.ASCII.GetBytes(requestBody.ToString()));

                responseMap.Clear();
                String response = GetHeader(ICAPTERMINATOR);
                responseMap = ParseHeader(response);

                responseMap.TryGetValue("StatusCode", out tempString);
                if (tempString != null)
                {
                    status = Convert.ToInt16(tempString);


                    if (status == 204) { return true; } //Unmodified

                    if (status == 200) //OK - The ICAP status is ok, but the encapsulated HTTP status will likely be different
                    {
                        response = GetHeader(HTTPTERMINATOR);

                        if (response.Contains("HTTP/1.1 200"))
                        {
                            return true;
                        }
                        throw new ICAPException(string.Format($"The file '{}' is potentially dangerous!", fullFileName));
                    }
                }
                throw new ICAPException("Unrecognized or no status code in response header.");
            }
        }

        private string BuildRequestHeaders(string fileName, int fileContentLength, int previewSize) {
            StringBuilder reqHeaders = new StringBuilder();
            StringBuilder respHeaders = new StringBuilder();

            HttpRequest request = HttpContext.Current.Request;

            reqHeaders.Append(String.Format("GET /{0} HTTP/1.1\r\n", fileName));
            reqHeaders.Append(String.Format("Host:{0}\r\n", "procreditbank.bg"));// sender.LocalEndPoint));
            reqHeaders.Append(String.Format("\r\n"));

            respHeaders.Append(String.Format("HTTP/1.1 200 OK\r\n", sender.LocalEndPoint));
            respHeaders.Append(String.Format("Content-Type: {0}\r\n", MimeMapping.GetMimeMapping(fileName)));
            respHeaders.Append(String.Format("Content-Length: {0}\r\n", fileContentLength));
            respHeaders.Append(String.Format("\r\n"));

            StringBuilder requestBody = new StringBuilder();
            requestBody.Append(String.Format("RESPMOD icap://{0}:{1}/ ICAP/{2}\r\n", serverHost, serverPort, VERSION));
            requestBody.Append(String.Format("Allow: 204\r\n"));
            requestBody.Append(String.Format("Host: {0}\r\n", serverHost));
            requestBody.Append(String.Format("X-Client-IP: {0}\r\n", sender.LocalEndPoint));
            requestBody.Append(String.Format("Preview: {0}\r\n", previewSize));
            requestBody.Append(String.Format("Encapsulated: req-hdr=0, res-hdr={0}, res-body={1}\r\n", reqHeaders.Length, reqHeaders.Length + respHeaders.Length));
            requestBody.Append(String.Format("\r\n"));

            requestBody.Append(reqHeaders.ToString());
            requestBody.Append(respHeaders.ToString());

            requestBody.Append(previewSize.ToString("X") + "\r\n");

            return requestBody.ToString();
        }

        /// <summary>
        /// Automatically asks for the servers available options and returns the raw response as a String.
        /// </summary>
        /// <returns>String of the raw response</returns>
        private string GetOptions()
        {
            byte[] msg = Encoding.ASCII.GetBytes(
                "OPTIONS icap://" + serverHost + "/ ICAP/" + VERSION + "\r\n"
                + "Host: " + serverHost + "\r\n"
                + "User-Agent: " + USERAGENT + "\r\n"
                + "Encapsulated: null-body=0\r\n"
                + "\r\n");
            sender.Send(msg);

            return GetHeader(ICAPTERMINATOR);
        }

        /// <summary>
        /// Receive an expected ICAP header as response of a request. The returned String should be parsed with parseHeader()
        /// </summary>
        /// <param name="terminator">Relative or absolute filepath to a file.</parm>
        /// <exception cref="ICAPException">Thrown when error occurs in communication with server</exception>
        /// <returns>String of the raw response</returns>
        private String GetHeader(String terminator)
        {
            byte[] endofheader = System.Text.Encoding.UTF8.GetBytes(terminator);
            byte[] buffer = new byte[stdRecieveLength];

            int n;
            int offset = 0;
            //stdRecieveLength-offset is replaced by '1' to not receive the next (HTTP) header.
            while ((offset < stdRecieveLength) && ((n = sender.Receive(buffer, offset, 1, SocketFlags.None)) != 0)) // first part is to secure against DOS
            {
                offset += n;
                if (offset > endofheader.Length + 13) // 13 is the smallest possible message (ICAP/1.0 xxx\r\n) or (HTTP/1.0 xxx\r\n)
                {
                    byte[] lastBytes = new byte[endofheader.Length];
                    Array.Copy(buffer, offset - endofheader.Length, lastBytes, 0, endofheader.Length);
                    if (endofheader.SequenceEqual(lastBytes))
                    {
                        return Encoding.ASCII.GetString(buffer, 0, offset);
                    }
                }
            }
            throw new ICAPException("Error in getHeader() method");
        }

        /// <summary>
        /// Given a raw response header as a String, it will parse through it and return a Dictionary of the result
        /// </summary>
        /// <param name="response">A raw response header as a String.</parm>
        /// <returns>Dictionary of the key,value pairs of the response</returns>
        private Dictionary<String, String> ParseHeader(String response)
        {
            Dictionary<String, String> headers = new Dictionary<String, String>();

            /****SAMPLE:****
             * ICAP/1.0 204 Unmodified
             * Server: C-ICAP/0.1.6
             * Connection: keep-alive
             * ISTag: CI0001-000-0978-6918203
             */
            // The status code is located between the first 2 whitespaces.
            // Read status code
            int x = response.IndexOf(" ", 0);
            int y = response.IndexOf(" ", x + 1);
            String statusCode = response.Substring(x + 1, y - x - 1);
            headers.Add("StatusCode", statusCode);

            // Each line in the sample is ended with "\r\n". 
            // When (i+2==response.length()) The end of the header have been reached.
            // The +=2 is added to skip the "\r\n".
            // Read headers
            int i = response.IndexOf("\r\n", y);
            i += 2;
            while (i + 2 != response.Length && response.Substring(i).Contains(':'))
            {
                int n = response.IndexOf(":", i);
                String key = response.Substring(i, n - i);

                n += 2;
                i = response.IndexOf("\r\n", n);
                String value = response.Substring(n, i - n);

                headers.Add(key, value);
                i += 2;
            }
            return headers;
        }

        /// <summary>
        /// A basic excpetion to show ICAP-related errors
        /// </summary>
        public class ICAPException : Exception
        {
            public ICAPException(string message)
                : base(message)
            {
            }

        }

        public void Dispose()
        {
            sender.Shutdown(SocketShutdown.Both);
            sender.Close();
            sender.Dispose();
            //fileStream.Close();
            //throw new NotImplementedException();
        }
    }
}
