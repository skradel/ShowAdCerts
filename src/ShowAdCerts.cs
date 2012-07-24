using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.DirectoryServices.Protocols;
using System.Security.Cryptography.X509Certificates;

namespace Zetetic.Ldap.Tools
{
    class ShowAdCerts
    {
        static void Main(string[] args)
        {
            Console.Error.WriteLine("ShowAdCerts v1.0, (c) 2012 Zetetic LLC");

            if (args.Length == 1 && args[0].EndsWith("?"))
            {
                Console.Error.WriteLine(@"Switches (all are optional): 

-h  host or domain name (default = default logon server)
-f  ldap filter         (default = userCertificate=*   )
-b  search base         (default = domain root NC      )
-v  (turn on cert validation of non-expired certs      )
-r  (dump raw cert data                                )
");

                System.Environment.ExitCode = 1;
                return;
            }

            string searchbase = null, filter = "(&(userCertificate=*))", host = "";
            bool validate = false, raw = false;

            try
            {
                for (int i = 0; i < args.Length; i++)
                {
                    switch (args[i])
                    {
                        case "-h":
                            host = args[++i];
                            break;

                        case "-r":
                            raw = true;
                            break;

                        case "-f":
                            filter = args[++i];
                            switch (filter.ToLowerInvariant())
                            {
                                case "computer":
                                    filter = "(&(userCertificate=*)(objectCategory=computer))";
                                    break;

                                case "user":
                                case "person":
                                    filter = "(&(userCertificate=*)(objectCategory=person))";
                                    break;
                            }
                            break;

                        case "-b":
                            searchbase = args[++i];
                            break;

                        case "-v":
                            validate = true;
                            break;

                        default:
                            Console.Error.WriteLine("Unknown argument {0}", args[i]);
                            break;
                    }
                }

                using (var conn = new LdapConnection(host))
                {
                    conn.SessionOptions.ProtocolVersion = 3;

                    if (string.IsNullOrEmpty(searchbase))
                    {
                        var e = ((SearchResponse)conn.SendRequest(new SearchRequest(
                            "", 
                            "(&(objectClass=*))", 
                            SearchScope.Base, 
                            "defaultNamingContext"))).Entries[0];

                        searchbase = e.Attributes["defaultNamingContext"][0].ToString();
                    }

                    var srch = new SearchRequest(searchbase, filter, SearchScope.Subtree, "userCertificate");
                    var pager = new PageResultRequestControl();
                    srch.Controls.Add(pager);

                    int count = 0;

                    while (true)
                    {
                        var resp = (SearchResponse)conn.SendRequest(srch);

                        foreach (SearchResultEntry se in resp.Entries)
                        {
                            if (!se.Attributes.Contains("userCertificate"))
                            {
                                continue;
                            }

                            Console.WriteLine("# {0}", ++count);
                            Console.WriteLine("dn: {0}", se.DistinguishedName);

                            foreach (var o in se.Attributes["userCertificate"].GetValues(typeof(byte[])))
                            {
                                byte[] bytes = (byte[])o;

                                try
                                {
                                    X509Certificate2 cert = new X509Certificate2(bytes);

                                    Console.WriteLine("subject: {0}", string.IsNullOrEmpty(cert.Subject) ? cert.SubjectName.Name : cert.Subject);
                                    Console.WriteLine("issuer: {0}", cert.Issuer);
                                    Console.WriteLine("thumbprint: {0}", cert.Thumbprint);
                                    Console.WriteLine("serial: {0}", cert.SerialNumber);
                                    
                                    var estr = cert.GetExpirationDateString();
                                    var expired = false;

                                    if (!string.IsNullOrEmpty(estr))
                                    {
                                        Console.WriteLine("exp: {0}", estr);
                                        DateTime dt;

                                        if (DateTime.TryParse(estr, out dt) && dt < DateTime.Now)
                                        {
                                            Console.WriteLine("expired: TRUE");
                                            expired = true;
                                        }
                                    }

                                    if (validate && !expired)
                                    {
                                        Console.WriteLine("valid: {0}", cert.Verify().ToString().ToUpperInvariant());
                                    }
                                }
                                catch (Exception e)
                                {
                                    Console.WriteLine("exception: {0}, {1}", e.GetType(), e.Message);
                                }

                                if (raw)
                                {
                                    var s = Convert.ToBase64String(bytes);

                                    Console.WriteLine("-----BEGIN CERTIFICATE-----"); 

                                    for (int i = 0; i < s.Length; i += 78)
                                    {
                                        Console.WriteLine(s.Substring(i, Math.Min(78, s.Length - i)));
                                    }

                                    Console.WriteLine("-----END CERTIFICATE-----");
                                }

                                Console.WriteLine("-");
                            }
                            Console.WriteLine("");
                        }

                        var rc = resp.Controls.SingleOrDefault(t => t is PageResultResponseControl) as PageResultResponseControl;

                        if (rc == null || rc.Cookie == null || rc.Cookie.Length == 0)
                            break;

                        pager.Cookie = rc.Cookie;
                    }
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Error type = {0}, message = {1}, stack = {2}", e.GetType(), e.Message, e.StackTrace);

                System.Environment.ExitCode = 2;
            }
        }
    }
}
