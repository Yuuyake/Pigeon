/*
| Emre Ekinci                                     
| yunusemrem@windowslive.com	                   
| 05550453800                                       
|                                      
|        
|      TODO:
            > VirusTotal NUGET API var kullan
            > Manuel Newtonsoft yükle
            > Config dosyasındakileri yaz belirt, IP port ..

*/
using System;
using System.Collections;
using System.Collections.Generic;
using System.Management.Automation;
using System.Text;
using Console = Colorful.Console;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Drawing;
using System.DirectoryServices;
using ADGroups.Properties;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Linq;
using log4net;
using System.Reflection;
using log4net.Config;
using System.Threading;
using System.Threading.Tasks;

namespace ADGroups {
    class MainClass {
        private static readonly ILog logger = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        public static string appSignature = "SOME";
        public static PrincipalContext principalContext = new PrincipalContext(ContextType.Domain);
        public static List<string> subGroups = new List<string>();

        static void Main(string[] args) {
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding  = Encoding.UTF8; 
            Console.WriteFormatted(Resources.banner, Color.LightGoldenrodYellow);
            // bu Encoding e dikkat
            List<string> ADGroups = new List<string>(File.ReadAllLines("ADGroups.txt", Encoding.GetEncoding("ISO-8859-9")));
            ADGroups = ADGroups.Where(s => !string.IsNullOrWhiteSpace(s)).Distinct().ToList();

            List<AGroup> ADGroupUsers = getGroupUsers3(ADGroups);
            Helpers.printToConsole(ADGroupUsers);
            Helpers.writeToFile(ADGroupUsers);
            logUsersToArcsight(ADGroupUsers);

            Console.WriteLine("\n\n ===============================  ALL DONE Look at \"Results\" folder =============================== ",Color.Yellow);
            //Console.ReadKey();
            Environment.Exit(0);
        }
        /// <summary>
        /// sends Syslogs to Arcsight with CEF format
        /// </summary>
        /// <param name="aDGroupUsers"></param>
        private static void logUsersToArcsight(List<AGroup> aDGroupUsers) {
            var logRepository = LogManager.GetRepository(Assembly.GetEntryAssembly());
            File.Create("log4net.config").Close();
            File.WriteAllText(Directory.GetCurrentDirectory() + "\\log4net.config", Resources.log4net);
            var configFile = new FileInfo(Directory.GetCurrentDirectory() + "\\log4net.config");
            XmlConfigurator.Configure(logRepository, configFile);
            string logFile = "logsSend.csv";
            if (!File.Exists(logFile))
                File.Create(logFile).Close();
            FileInfo fi = new FileInfo(logFile);
            if (fi.Length / 1048576 >= 1) {
                File.Copy(logFile, Directory.GetCurrentDirectory() + "\\BACKUP " + DateTime.Now.ToString("yyyy.dd.M_HH.mm.ss") + " " + logFile, true);
                File.Delete(logFile);
            }
            int megaCount = 1;
            foreach (AGroup group in aDGroupUsers) {
                foreach (User user in group.members) {
                    if (megaCount % 400 == 0) {
                        Console.WriteFormatted("\n Waiting to load more...\n",Color.Yellow);
                        Thread.Sleep(2000);
                    }
                    megaCount++;
                    //            "CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension"
                    var message = "CEF:0|PigeonAdLogger|PigeonAdLogger|1.0|" + appSignature + "|ActiveDirectoryGroupUsers|Mid|act=%<dispositionString> dvc=%<sourceServer> dst=%<destination> dhost=%<urlHost> dpt=%<port> src=%<source> spt=%<clientSourcePort> suser=" + user.sicil + " destinationTranslatedPort=%<proxySourcePort> rt=%<time>000 in=%<bytesSent> out=%<bytesReceived> requestMethod=%<method> requestClientApplication=%<=userAgent> reason=%<scanReasonString> cs1Label=user cs1=" + user.sicil + " cs2Label=ADGroup cs2=" + group.name + " cs3Label=FullName cs3=" + user.fullname + " cs4Label=Mobile cs4=" + user.mobile.Replace("+90", "")  + " cn1=%<=dispositionNumber> cn2=%<scanDuration> request=%<=url>";
                    logger.Info(message);
                    string toFile = megaCount-1 + "," + DateTime.Now.ToString() + "," + appSignature + "," + user.sicil + "," + group.name + "," + user.fullname + "," + user.mobile;
                    // print to console
                    Console.WriteFormatted("\n" + toFile,Color.Green);
                    // print to file
                    File.AppendAllLines(logFile, new[] { toFile });
                }
            }
            File.Delete("log4net.config");

        }
        /// <summary>
        /// takes list of names of AD Groups and returns info(members etc.) about them
        /// </summary>
        /// <param name="domain"></param>
        /// <param name="group"></param>
        /// <returns></returns>
        static public List<AGroup> getGroupUsers3(List<string> ADgroups) {
            List<AGroup> allUsers = new List<AGroup>();
            foreach (string currGroup in ADgroups) {
                Console.Write("\n Reading group: " + currGroup + " ...");
                List<User> members = new List<User>();
                GroupPrincipal grp = GroupPrincipal.FindByIdentity(principalContext, currGroup);
                if(grp == null) { Console.WriteFormatted("\n\t!!!Cannot read group: " + currGroup + " >> passing",Color.Red); continue; }
				List<User> gr1 = new List<User>();
				List<User> gr2 = new List<User>();
                var users = GetGroupMembersName(currGroup);
                //List<Principal> users = grp.GetMembers(true).ToList();
                var task1 = Task.Factory.StartNew(() => gr1 = extractUsers(0, users.Count()/2, users));
				var task2 = Task.Factory.StartNew(() => gr2 = extractUsers(users.Count()/2, users.Count(), users));
                Task.WaitAll(task1,task2);
				members.AddRange(gr1);
				members.AddRange(gr2);
                allUsers.Add(new AGroup(members, currGroup));
                grp.Dispose();
                //showList(members, currGroup);
            }
            principalContext.Dispose();
            return allUsers;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="start"></param>
        /// <param name="end"></param>
        /// <param name="grp"></param>
        /// <returns></returns>
		static public List<User> extractUsers(int start, int end, List<string> members ) {
            Console.Write("\n");
            List<User> users = new List<User>();
            Color myC = start > 0 ? Color.Cyan : Color.Yellow;

            UserPrincipalExt extUser;
            for ( int x = start; x<end; x++ ){
                if( start > 0 )
                    Console.Write("\r User " + x + "     ");
                try {
                    extUser = UserPrincipalExt.FindByIdentity(principalContext, IdentityType.SamAccountName, members[x]);
                    users.Add(new User(extUser));
                }
                catch (Exception ee) {
                    Console.WriteFormatted("\n\t| Exception user" + x + "(" + members[x] + "): " + ee.Message + "\n", Color.Red);
                }
			}
            return users;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="group"></param>
        /// <returns></returns>
        private static List<string> GetGroupMembersName(string groupName) {
            var members = new List<string>();
            DirectoryEntry rootDir = new DirectoryEntry("your LDAP LOC");
            DirectorySearcher ds = new DirectorySearcher(rootDir);
            ds.SearchScope = SearchScope.Subtree;
            ds.Filter = "(&(cn=" + groupName + ")(objectCategory=group))";
            var results = ds.FindAll();
            if (results.Count <= 0) { return new List<string>();}
            var groupPath = results[0].Path;

            //new DirectoryEntry("LDAP://CN=" + groupName + ",OU=Exchange Dist. Grup,OU=Exchange,DC=YOURDOMAIN,DC=YOURDOMAIN,DC=com,DC=tr");
            DirectoryEntry myGroup = new DirectoryEntry(groupPath);
            while (true) {
                PropertyValueCollection memberDns = null;
                try {
                    memberDns = myGroup.Properties["member"];
                }
                catch (Exception ee) {
                    Console.WriteFormatted("\n | Exception: " + ee.Message,Color.Red);
                    break;
                }
                foreach (var member in memberDns) {
                    try {
                        /*
                        "CN=Enterprise Admins,OU=Exchange Dist. Grup,OU=Exchange,DC=YOURDOMAIN,DC=YOURDOMAIN,DC=com,DC=tr"
                            Object type = Group alanını araştır
                            kişiyse dm_p olup olmadığına bak
                        */
                        string temp = member.ToString();
                        short startIndex = (short)(temp.IndexOf('-') + 2);
                        temp = "P" + temp.Substring(startIndex, temp.IndexOf(',') - startIndex);
                        if (temp.Contains('=')) {
                            var subName = temp.Substring(temp.IndexOf('=') + 1);
                            //Console.Write("\n | Passing Group: " + subName);
                            //continue;
                            if (subGroups.Contains(subName) == false) {
                                subGroups.Add(subName);
                                Console.Write("\n | Group: " + subName);
                                members.AddRange(GetGroupMembersName(subName));
                            }
                            else
                                continue;
                        }
                        else
                            members.Add(temp);
                    }
                    catch (Exception ee) {
                        Console.WriteFormatted("\n\t| Exception user(" + member.ToString().Split(',')[0] + "): " + ee.Message + "\n", Color.Red);
                    }
                }// END OF for loop
                if (memberDns.Count == 0) break;
                try {
                    myGroup.RefreshCache(new[] { $"member;range={members.Count}-*", "member" });
                }
                catch (System.Runtime.InteropServices.COMException e) {
                    if (e.ErrorCode == unchecked((int)0x80072020)) { //no more results
                        break;
                    }
                    throw;
                }
            }
            return members;
        }
        /// <summary>
        /// Presents an Active Directory Group with members,name... etc
        /// </summary>
        public class AGroup {
            public string name;
            public List<User> members;
            public AGroup(List<User> members, string currGroup) {
                this.members = members;
                this.name = currGroup;
            }
        }
        /// <summary>
        /// 
        /// </summary>
        public class User {
            public string name      = "?";
            public string surname   = "?";
            public string fullname  = "?";

            public string sicil;
            public string phone     = "?";
            public string mobile    = "?";
            public string mail      = "?";

            public User(UserPrincipalExt _user) {
                try {
                    var user = (UserPrincipalExt)_user;
                    name        = user.GivenName ?? "?";
                    surname     = user.Surname ?? "?";
                    fullname    = name + " " + surname ?? "?";
                    sicil       = user.SamAccountName ?? "?";
                    phone       = user.VoiceTelephoneNumber ?? "?";
                    mobile      = user.ExtensionAttribute11 ?? "?";
                    //mail      = user.EmailAddress ?? "?";
                }
                catch (InvalidDataException ee) {
                    Console.Write("\n | " + ee.Message);
                }
            }
            public User(string _name = "?", string _surname = "?", string _fullname = "?", string _sicil = "?", string _phone = "?", string _mail = "?") {
                name        = _name;
                surname     = _surname;
                fullname    = _fullname;
                sicil       = _sicil;
                phone       = _phone;
                //mail      = _mail;
            }
        }
        /// <summary>
        /// Extends the UserPrincipal( user info class ) to get extension attributes like mobile phone etc... 
        /// </summary>
        [DirectoryRdnPrefix("CN")]
        [DirectoryObjectClass("Person")]
        public class UserPrincipalExt : UserPrincipal {
            const string extName11 = "extensionAttribute11";
            const string extName2 = "extensionAttribute2";
            const string extName3 = "extensionAttribute3";

            // Inplement the constructor using the base class constructor. 
            public UserPrincipalExt(PrincipalContext context) : base(context) { }

            // Implement the constructor with initialization parameters.    
            public UserPrincipalExt(PrincipalContext context, string samAccountName, string password, bool enabled)
                : base(context, samAccountName, password, enabled) { }

            [DirectoryProperty(extName11)]
            public string ExtensionAttribute11 { 
                get { return ExtensionGet(extName11).Length != 1 ? string.Empty : (string)ExtensionGet(extName11)[0]; }
                set { ExtensionSet(extName11, value); }
            }
            public new static UserPrincipalExt FindByIdentity(PrincipalContext context, string identityValue) {
                return (UserPrincipalExt)FindByIdentityWithType(context, typeof(UserPrincipalExt), identityValue);
            }
            public new static UserPrincipalExt FindByIdentity(PrincipalContext context, IdentityType identityType, string identityValue) {
                return (UserPrincipalExt)FindByIdentityWithType(context, typeof(UserPrincipalExt), identityType, identityValue);
            }
        }

    }
}