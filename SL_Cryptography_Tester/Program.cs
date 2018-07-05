using System;
using System.Diagnostics;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;

namespace SL_Cryptography_Tester
{
    class Program
    {
        private static Stopwatch timer; 

        static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Welcome to SCP:SL Cryptography Tester");
            Console.WriteLine("Copyright by Lukasz \"zabszk\" Jurczyk, 2018");
            Console.WriteLine("This software includes Bouncy Castle C# API developed by The Legion of the Bouncy Castle under The MIT License.");
            Console.WriteLine("");
            Console.WriteLine("Let's start");
            Console.WriteLine("");

            timer = new Stopwatch();
            timer.Start();

            PrintTask("Preparing");
            AsymmetricCipherKeyPair SessionKeys = null;
            RandomNumberGenerator rng = null;
            byte[] challengeData = null;
            string challengeCode = null;
            string signature = null;
            string pem = null;
            string privPem = null;
            try
            {
                rng = new RNGCryptoServiceProvider();
                challengeData = new byte[32];
                
                PrintOK();
            }
            catch (Exception e)
            {
                PrintFail(e);
            }

            PrintTask("Generating ECDSA keys");
            try
            {
                SessionKeys = ECDSA.GenerateKeys();
                PrintOK();
            }
            catch (Exception e)
            {
                PrintFail(e);
            }

            PrintTask("Generating crypto-secure random data");
            try
            {
                rng.GetBytes(challengeData);
                challengeCode = Convert.ToBase64String(challengeData);
                challengeCode = "auth-" + challengeCode;
                PrintOK();
            }
            catch (Exception e)
            {
                PrintFail(e);
            }

            PrintTask("Signing data using ECDSA Private Key");
            try
            {
                signature = ECDSA.Sign(challengeCode, SessionKeys.Private);
                PrintOK();
            }
            catch (Exception e)
            {
                PrintFail(e);
            }

            PrintTask("Converting ECDSA Public Key to PEM format");
            try
            {
                pem = ECDSA.KeyToString(SessionKeys.Public);
                PrintOK();
            }
            catch (Exception e)
            {
                PrintFail(e);
            }

            PrintTask("Converting ECDSA Private Key to PEM format");
            try
            {
                privPem = ECDSA.KeyToString(SessionKeys.Private);
                PrintOK();
            }
            catch (Exception e)
            {
                PrintFail(e);
            }

            Console.WriteLine();
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            timer.Stop();
            Console.WriteLine("Test completed without any errors in " + Math.Round(timer.Elapsed.TotalSeconds) + "." + timer.Elapsed.Milliseconds + " second(s)");
            Console.WriteLine();
            PrintKeyValue("Challenge", challengeCode);
            PrintKeyValue("Signature", signature);
            PrintKeyValue("Public Key", "\n" + pem);
            PrintKeyValue("Private Key", "\n" + privPem);
            while (true) Console.ReadKey(true);
        }

        static void PrintKeyValue(string key, string value)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write(key + ": ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(value);
            Console.WriteLine();
        }

        static void PrintTask(string text)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("[" + Math.Round(timer.Elapsed.TotalSeconds) + "." + timer.Elapsed.Milliseconds + "] " + text + "...");
        }

        static void PrintOK()
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" [");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("OK " + Math.Round(timer.Elapsed.TotalSeconds) + "." + timer.Elapsed.Milliseconds);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("]");
        }

        static void PrintFail(Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" [");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write("FAIL " + Math.Round(timer.Elapsed.TotalSeconds) + "." + timer.Elapsed.Milliseconds);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("]");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("=== Exception ===");
            Console.WriteLine("Message: " + ex.Message);
            Console.WriteLine("Stack Trace: " + ex.StackTrace);
            while (true) Console.ReadKey(true);
        }
    }
}
