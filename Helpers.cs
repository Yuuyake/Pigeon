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
using ADGroups;

namespace ADGroups {
    class Helpers {

        /// <summary>
        /// prints contents of string list
        /// </summary>
        /// <param name="list"></param>
        /// <param name="name"></param>
        static public void showList(List<string> list, string name) {
            Console.WriteFormatted("\n Looking for \"" + name + "\":", Color.DarkOrange);
            Console.WriteFormatted("\n ┌───────────────────────────────────────────────────────────────────────────────────── ", Color.DarkOrange);
            int counter = 0;
            foreach (string ss in list) {
                if (counter % 3 == 0)
                    Console.WriteFormatted("\n │", Color.White);
                Console.WriteFormatted("       \t       ", Color.White);
                Console.BackgroundColor = Color.Blue;
                Console.WriteFormatted(ss, Color.White);
                Console.BackgroundColor = Color.Black;
                counter++;
            }
            Console.WriteFormatted("\n └───────────────────────────────────────────────────────────────────────────────────── \n\n", Color.DarkOrange);
        }
        static public void writeToFile(List<MainClass.AGroup> ADgroups) {
            if (Directory.Exists(@"Results") == true)
                Directory.Delete(@"Results", true);
            Directory.CreateDirectory(@"Results");
            foreach (MainClass.AGroup group in ADgroups) {
                var groupFileName = @"Results\" + group.name + ".txt";
                File.Create(groupFileName).Close();
                File.WriteAllLines(groupFileName, group.members.Select(ss => ss.sicil));
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="aDGroupUsers"></param>
        public static void printToConsole(List<MainClass.AGroup> adGroups) {
            foreach (MainClass.AGroup adGroup in adGroups) {
                Console.WriteFormatted("\n Looking for \"" + adGroup.name + "\":", Color.DarkOrange);
                Console.WriteFormatted("\n ┌───────────────────────────────────────────────────────────────────────────────────── ", Color.DarkOrange);
                int counter = 0;
                foreach (MainClass.User ss in adGroup.members) {
                    if (counter % 3 == 0)
                        Console.WriteFormatted("\n │", Color.White);
                    Console.WriteFormatted("       \t       ", Color.White);
                    Console.BackgroundColor = Color.Blue;
                    Console.WriteFormatted(ss.sicil, Color.White);
                    Console.BackgroundColor = Color.Black;
                    counter++;
                }
                Console.WriteFormatted("\n └───────────────────────────────────────────────────────────────────────────────────── \n\n", Color.DarkOrange);
            }
        }

        #region ALTERNATIVES
        // =======================================================================================================
        // ============================================                ===========================================
        // ============================================  ALTERNATIVES  ===========================================
        // ============================================                ===========================================
        // =======================================================================================================

        /// <summary>
        /// takes list of names of AD Groups and returns info(members etc.) about them
        /// </summary>
        /// <param name="ADgroups"></param>
        /// <returns></returns>
        static List<MainClass.AGroup> getGroupUsers1(List<string> ADgroups) {
            List<MainClass.AGroup> allUsers = new List<MainClass.AGroup>();
            //System.Diagnostics.ProcessStartInfo proccessStartInfo = new System.Diagnostics.ProcessStartInfo("cmd", "net user " + "YOURSICIL" + "/domain");
            foreach (string currGroup in ADgroups) {
                List<string> lines = new List<string>();
                List<string> members = new List<string>();
                PSDataCollection<PSObject> outputCollection = new PSDataCollection<PSObject>();
                using (PowerShell psInstance = PowerShell.Create()) {
                    psInstance.AddScript("net group /domain \"" + currGroup + "\"");
                    var result = psInstance.BeginInvoke<PSObject, PSObject>(null, outputCollection);
                    Console.Write("\n │ Gettting Users for Group: " + "\"" + currGroup + "\" ... ");
                    result.AsyncWaitHandle.WaitOne();
                    int counter = -1;
                    foreach (PSObject outputItem in outputCollection) {
                        counter++;
                        if (counter < 7)
                            continue;
                        lines.Add(outputItem.BaseObject.ToString());
                    }
                }
                try {
                    if (lines.Remove("-------------------------------------------------------------------------------") == false ||
                        lines.Remove("The command completed successfully.") == false) {
                        throw new ArgumentException(" ");
                    }
                    lines.RemoveAll(p => string.IsNullOrEmpty(p));
                    var tempall = string.Join("", lines.ToArray());
                    tempall = Regex.Replace(tempall, " {2,}", " "); // removes multiple whitespaces with one
                    members = new List<string>(tempall.Split(' '));
                    allUsers.Add(new MainClass.AGroup(members.Select(ss => new MainClass.User(_sicil: ss)).ToList(), currGroup));
                    Helpers.showList(lines, currGroup);
                }
                catch {
                    Console.WriteFormatted("\n │ Probably missed some users ... Check it. ", Color.Red);
                }
            }
            return allUsers;
        }
        /// <summary>
        /// takes list of names of AD Groups and returns info(members etc.) about them
        /// </summary>
        /// <param name="userName"></param>
        static List<MainClass.AGroup> getGroupUsers2(List<string> ADGroups) {
            List<MainClass.AGroup> allUsers = new List<MainClass.AGroup>();
            Process cmd = new Process();
            cmd.StartInfo.FileName = "cmd.exe";
            cmd.StartInfo.RedirectStandardInput = true;
            cmd.StartInfo.RedirectStandardOutput = true;
            cmd.StartInfo.CreateNoWindow = true;
            cmd.StartInfo.UseShellExecute = false;

            foreach (string currGroup in ADGroups) {
                List<string> members = new List<string>();
                Console.Write("\n │ Gettting Users for Group: " + "\"" + currGroup + "\" ... ");
                cmd.Start();
                cmd.StandardInput.WriteLine("net group /domain \"" + currGroup + "\"");
                cmd.StandardInput.Flush();
                cmd.StandardInput.Close();
                cmd.WaitForExit();
                var result = cmd.StandardOutput.ReadToEnd();
                try {
                    result = result.Substring(result.IndexOf("---") + 1);
                    result = result.Substring(0, result.IndexOf("C:\\Us"));
                    result = result.Replace("------------------------------------------------------------------------------", "");
                    result = result.Replace("The command completed successfully.", "").Replace("\r", "").Replace("\n", "");
                    result = Regex.Replace(result, " {2,}", " "); // removes multiple whitespaces with one
                    members = new List<string>(result.Split(' '));
                    allUsers.Add(new MainClass.AGroup(members.Select(ss => new MainClass.User(_sicil: ss)).ToList(), currGroup));
                    Helpers.showList(members, currGroup);
                }
                catch {
                    Console.WriteFormatted("\n │ Probably missed some users ... Check it. ", Color.Red);
                }
            }
            return allUsers;
        }

        #endregion
    }
}
