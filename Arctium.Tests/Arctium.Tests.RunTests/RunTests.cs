using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using Arctium.Tests.Standards;
using Arctium.Tests.Standards.PKCS1;
using Arctium.Tests.Core.Attributes;
using Arctium.Tests.Core;
using System.Threading;
using System.Threading.Tasks;
using System.Configuration;
using System.Text.RegularExpressions;

namespace Arctium.Tests.RunTests
{
    public class RunTests
    {
        public class FinishedTestsInfo
        {
            public string ClassName;
            public string MethodName;
            public List<TestResult> Results;

            public FinishedTestsInfo(string className, string methodName, List<TestResult> results)
            {
                ClassName = className;
                MethodName = methodName;
                Results = results;
            }
        }

        public class ConsoleOutput
        {
            object _lock = new object();
            int appendFinishedTestCursorTop = 4;
            public int totalSuccess = 0;
            public int totalFail = 0;
            private string displayFormat;
            List<TestResult> allTests;

            public int TotalTests = 0;
            int finishedTests = 0;

            public ConsoleOutput(string displayFormat)
            {
                this.displayFormat = displayFormat;
                allTests = new List<TestResult>();
            }

            public void ShowFinishedTestResults(FinishedTestsInfo info)
            {
                Monitor.Enter(_lock);

                finishedTests++;
                allTests.AddRange(info.Results);

                foreach (var t in info.Results)
                {
                    if (t.Success)
                    {
                        totalSuccess++;
                    }
                    else
                    {
                        totalFail++;
                    }
                }

                AppendFinishedTestsList(info);

                Monitor.Exit(_lock);
            }

            private void AppendFinishedTestsList(FinishedTestsInfo info)
            {
                if (displayFormat == "allTests")
                {
                    foreach (var t in info.Results)
                    {
                        string m = t.Name;
                        // appendFinishedTestCursorTop++;
                        // Console.CursorTop = appendFinishedTestCursorTop - 1;

                        if (!t.Success)
                        {
                            if (t.Exception != null)
                            {
                                m += "(" + t.Exception.Message + ")";
                            }

                            m = "FAIL: " + m;
                            Console.ForegroundColor = ConsoleColor.DarkMagenta;
                        }

                        Console.WriteLine(m);

                        Console.ForegroundColor = ConsoleColor.Gray;
                    }
                }
                else if (displayFormat == "liveSummary")
                {
                    for (int i = 0; i < 3; i++)
                    {
                        Console.SetCursorPosition(0, i);
                        for (int j = 0; j < 20; j++) Console.Write(" ");
                    }

                    Console.SetCursorPosition(0, 0);
                    Console.Write("success: " + totalSuccess);
                    Console.SetCursorPosition(0, 1);
                    Console.Write("fail: " + totalFail);
                    Console.SetCursorPosition(0, 2);
                    Console.Write(string.Format("completed: {0} / {1} ({2:0.00}%)", finishedTests, TotalTests, 100 * ((double)finishedTests / TotalTests)));
                }
                else if (displayFormat == "class-summary")
                {

                }
                else throw new Exception("invalid value for tests display format");
            }
        }

        public static ConsoleOutput consoleOutput = new ConsoleOutput(ConfigurationManager.AppSettings.Get("console-tests-display-format"));
        static List<Task> tasks = new List<Task>();
        private static string filterClassRegex;
        private static string methodRegex;

        static void SetArgs(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                var arg = args[i + 1];
                switch (args[i])
                {
                    case "-classRegex":
                        filterClassRegex = arg;
                        break;
                    case "-methodRegex":
                        methodRegex = arg;
                        break;
                    default:
                        break;
                }

                i++;
            }
        }

        public static void Run(string[] args)
        {
            SetArgs(args);




            var testClasses = FindTestClasses();
            testClasses = FilterTests(testClasses);
            var allTestMethods = testClasses.SelectMany(c => c.GetMethods().Where(method => method.GetCustomAttributes(typeof(TestMethodAttribute)).Any()).ToList()).ToList();

            var methodsToRun = FilterByMethodName(allTestMethods);
            methodsToRun = methodsToRun.OrderBy(method => method.GetCustomAttribute<TestMethodAttribute>().ExpectedDurationInSeconds).ToList();

            RunTestMethods(methodsToRun);

            Task.WaitAll(tasks.ToArray());
            Console.WriteLine("- END -");
        }

        static List<Type> FilterTests(List<Type> tests)
        {
            string filter = filterClassRegex;

            if (!string.IsNullOrEmpty(filter))
            {
                return tests.Where(t => Regex.Match(t.Name, filter).Success).ToList();
            }

            return tests;
        }

        static List<Type> FindTestClasses()
        {
            var testAssemblies = typeof(RunTests).Assembly.GetReferencedAssemblies().Where(asm => asm.Name.StartsWith("Arctium."));
            var assemblies = testAssemblies.Select(asm => Assembly.Load(asm));
            var allTypes = assemblies.SelectMany(asm => asm.GetTypes());
            var testClasses = new List<Type>();

            foreach (Type type in allTypes)
            {
                if (type.GetCustomAttribute<TestsClassAttribute>() != null)
                {
                    testClasses.Add(type);
                }
            }

            return testClasses;
        }

        private static void RunTestMethods(List<MethodInfo> methodsToRun)
        {
            // need to investigate (nice to have if makes sens):
            // instead of creating 'var instance = activator.createinstance'
            // for each method separtely, better to create instance onec? (group method by parent class?)
            // ----

            List<List<MethodInfo>> groups = SplitToEqualSizeGroups(methodsToRun, 25);
            consoleOutput.TotalTests += methodsToRun.Count;

            foreach (var g in groups)
            {
                var task = Task.Factory.StartNew((group) =>
                {
                    // Thread.CurrentThread.Priority = ThreadPriority.Highest;
                    foreach (var meth in (List<MethodInfo>)group)
                    {
                        var returnType = meth.ReturnType;
                        var methodName = meth.Name;
                        List<TestResult> res = new List<TestResult>();
                        var instance = Activator.CreateInstance(meth.DeclaringType);

                        if (returnType == typeof(void))
                        {
                            try
                            {
                                meth.Invoke(instance, new object[0]);
                                res.Add(new TestResult(methodName, true));
                            }
                            catch (Exception)
                            {
                                res.Add(new TestResult(methodName, false));
                            }
                        }
                        else
                        {
                            object objResults = meth.Invoke(instance, new object[0]);
                            res = (List<TestResult>)objResults;
                        }

                        
                        // testResults.AddRange(res);

                        var finishedInfo = new FinishedTestsInfo(meth.DeclaringType.Name, meth.Name, res);
                        consoleOutput.ShowFinishedTestResults(finishedInfo);
                    }
                }, g);

                tasks.Add(task);
            }
        }

        private static List<MethodInfo> FilterByMethodName(List<MethodInfo> members)
        {
            if (string.IsNullOrEmpty(methodRegex)) return members;

            return members.Where(t => Regex.Match(t.Name, methodRegex).Success).ToList();
        }

        private static List<List<MethodInfo>> SplitToEqualSizeGroups(List<MethodInfo> methods, int groupsCount)
        {
            List<List<MethodInfo>> res = new List<List<MethodInfo>>();

            if (methods.Count == 0) return res;

            int inOneGroup = (int)Math.Ceiling((double)methods.Count / (double)groupsCount);
            int countAfterSplit = (int)Math.Ceiling((double)methods.Count / (double)inOneGroup);

            for (int i = 0; i < countAfterSplit; i++)
            {
                List<MethodInfo> gr = new List<MethodInfo>();
                int start = inOneGroup * i;

                for (int j = start; j < start + inOneGroup && j < methods.Count; j++)
                {
                    gr.Add(methods[j]);
                }

                res.Add(gr);
            }

            return res;

            //List<List<MethodInfo>> results = new List<List<MethodInfo>>();
            //int itemsInGroup = ((methods.Count + groupsCount - 1) / groupsCount) * groupsCount;
            //itemsInGroup = itemsInGroup < 1 ? 1 : itemsInGroup;

            //for (int i = 0; i < groupsCount; i++)
            //{
            //    List<MethodInfo> group = new List<MethodInfo>();
            //    int idx = (itemsInGroup * i);

            //    for (int j = 0; j < itemsInGroup && (idx + j) < methods.Count; j++)
            //    {
            //        group.Add(methods[idx + j]);
            //    }

            //    results.Add(group);
            //}

            //for (int i = 0; i < remainder; i++)
            //{
            //    results[results.Count - 1].Add(methods[methods.Count - 1 - i]);
            //}

            // return results;
        }

        static void ReferenceAssemblies()
        {
            // getreferenceassemblies doesn't work without reference in code
            PKCSv2_2API_Tests t;
            RFC7748_Tests asdf = new RFC7748_Tests();
        }
    }
}
