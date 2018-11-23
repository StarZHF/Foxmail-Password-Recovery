using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace foxDecode
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Title = "FoxMail Password Decoder.";
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            var foxPath = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Classes\Foxmail.url.mailto\Shell\open\command").GetValue("").ToString();
            foxPath = foxPath.Remove(foxPath.LastIndexOf("Foxmail.exe")).Replace("\"", "") + @"Storage\";
            foreach (var dir in Directory.GetDirectories(foxPath, "*@*", SearchOption.TopDirectoryOnly))
            {
                string eMail = dir.Substring(dir.LastIndexOf("\\") +1);
                string userData = dir + @"\Accounts\Account.rec0";
                    // Read the file into <bits>
                    var fs = new FileStream(userData, FileMode.Open);
                    var len = (int)fs.Length;
                    var bits = new byte[len];

                    bool accfound = false;
                    string buffer = "";
                    int ver = 0;

                    fs.Read(bits, 0, len);

                    // Check if the file version
                    if (bits[0] == 0xD0)
                    {
                    // Version 6.X
                        ver = 0;
                    }
                    else
                    {
                    // Version 7.0 and 7.1
                    ver = 1;
                    }
                    // Loop to filter out non alphanumeric characters. Form word from individual character
                    // to see if it is the interested data
                    for (int jx = 0; jx < len; ++jx)
                    {
                        // Filter out not alphanumeric character
                        if (bits[jx] > 0x20 && bits[jx] < 0x7f && bits[jx] != 0x3d)
                        {
                            // Concat to from word
                            buffer += (char)bits[jx];
                       // Console.Write(buffer);
                            // Check if the next word is going to the user account
                            string acc = "";
                            if (buffer.Equals("Account") || buffer.Equals("POP3Account"))
                            {
                                // Offset
                                int index = jx + 9;

                                // Additional offset required for version 6.5
                                if (ver == 0)
                                {
                                    index = jx + 2;
                                }
                            // Loop till the entire data is extracted 
                            // (Data is in alphanumeric character, non alphanumeric mean end of data)
                                while (bits[index] > 0x20 && bits[index] < 0x7f)
                                {
                                    acc += (char)bits[index];
                                    index++;
                                }
                                // Flag to indicate account found
                                accfound = true;

                                // Shift the current "pointer" to the end index of the data
                                jx = index;
                            }
                            // If there is an user account, check for its password
                            else if (accfound && (buffer.Equals("Password") || buffer.Equals("POP3Password")))
                            {
                                int index = jx + 9;
                                if (ver == 0)
                                {
                                    index = jx + 2;
                                }
                                string pw = "";

                                while (bits[index] > 0x20 && bits[index] < 0x7f)
                                {
                                    pw += (char)bits[index];
                                    index++;
                                }
                                    accountWriter(eMail, decodePW(ver, pw));
                                jx = index;
                                break;
                            }
                        }
                        else
                        {
                            buffer = "";
                        }   
                    }
                    fs.Close();
               }
            Console.ReadKey();
        }

        static void accountWriter(string eMail, string pass)
        {
            Console.WriteLine("----------------------------");
            Console.WriteLine(String.Format("E-Mail: {0}", eMail));
            Console.WriteLine(String.Format("Password: {0}", pass));
            Console.WriteLine("----------------------------");
        }

        /* Foxmail password decoder
         * Credit: Jacob Soo
         * https://github.com/jacobsoo
         */
        public static String decodePW(int v, String pHash)
        {
            String decodedPW = "";

            int[] a = { '~', 'd', 'r', 'a', 'G', 'o', 'n', '~' };
            int[] v7a = { '~', 'F', '@', '7', '%', 'm', '$', '~' };
            int fc0 = Convert.ToInt32("5A", 16);


            if (v == 1)
            {
                a = null;
                a = v7a;
                v7a = null;
                fc0 = Convert.ToInt32("71", 16);
            }


            int size = pHash.Length / 2;
            int index = 0;
            int[] b = new int[size];
            for (int i = 0; i < size; i++)
            {
                b[i] = Convert.ToInt32(pHash.Substring(index, 2), 16);
                index = index + 2;
            }

            int[] c = new int[b.Length];

            c[0] = b[0] ^ fc0;
            Array.Copy(b, 1, c, 1, b.Length - 1);

            while (b.Length > a.Length)
            {
                int[] newA = new int[a.Length * 2];
                Array.Copy(a, 0, newA, 0, a.Length);
                Array.Copy(a, 0, newA, a.Length, a.Length);
                a = null;
                a = newA;
                newA = null;

            }

            int[] d = new int[b.Length];

            for (int i = 1; i < b.Length; i++)
            {
                d[i - 1] = b[i] ^ a[i - 1];

            }

            int[] e = new int[d.Length];

            for (int i = 0; i < d.Length - 1; i++)
            {
                if (d[i] - c[i] < 0)
                {
                    e[i] = d[i] + 255 - c[i];

                }

                else
                {
                    e[i] = d[i] - c[i];
                }

                decodedPW += (char)e[i];
            }


            return decodedPW;
        }
    }

}