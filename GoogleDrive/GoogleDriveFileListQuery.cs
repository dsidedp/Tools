using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;

namespace DSide.GoogleDrive
{
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    public class GoogleDriveFileListQuery
    {
        public string Name { get; } = null;
        public string[] Parents { get; } = null;
        public IDictionary<string, string> Properties { get; } = null;

        public static string Parse(Expression<Func<GoogleDriveFileListQuery, bool>> filter)
        {
            var v = new Visitor();
            v.Visit(filter.Body);
            var args = new Stack<string>();

            while (v.QueryParts.Count > 0)
            {
                var arg = v.QueryParts.Pop();
                if (arg == OrToken)
                {
                    var orLeft = args.Pop();
                    var orRight = args.Pop();
                    args.Push($"({orLeft}) or ({orRight})");
                }
                else if (arg == AndToken)
                {
                    var andLeft = args.Pop();
                    var andRight = args.Pop();
                    args.Push($"({andLeft}) and ({andRight})");
                }
                else if (arg == NotToken)
                {
                    var notOp = args.Pop();
                    args.Push($"not {notOp}");
                }
                else
                {
                    args.Push(arg.ToString());
                }
            }

            if (args.Count == 1) return args.Pop();
            throw new ApplicationException("Cant parse query.");
        }

        private static readonly object OrToken = new object();
        private static readonly object AndToken = new object();
        private static readonly object NotToken = new object();

        private GoogleDriveFileListQuery() { }

        private class Visitor : ExpressionVisitor
        {
            private static readonly List<(MethodInfo Check, MethodInfo Process)> ComplexRules;
            private static readonly string IndexerPropertyName = typeof(IDictionary<string, string>).GetProperties().Single(x => x.GetIndexParameters().Any()).GetGetMethod().Name;
            static Visitor()
            {
                var m = typeof(Visitor).GetMethods(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);
                ComplexRules = m.Select(x => (m.SingleOrDefault(c => c.Name == $"Should{x.Name}"), x)).Where(x => x.Item1 != null).ToList();
            }

            public Stack<object> QueryParts { get; } = new Stack<object>();

            public override Expression Visit(Expression node)
            {
                switch (node.NodeType)
                {
                    case ExpressionType.AndAlso:
                        QueryParts.Push(AndToken);
                        return base.Visit(node);
                    case ExpressionType.OrElse:
                        QueryParts.Push(OrToken);
                        return base.Visit(node);
                    case ExpressionType.Not:
                        QueryParts.Push(NotToken);
                        return base.Visit(node);
                    case ExpressionType.Conditional when node is ConditionalExpression cond:
                        return TryEvalConditional(cond) ? Visit(cond.IfTrue) : Visit(cond.IfFalse);
                }

                foreach (var (check, process) in ComplexRules)
                {
                    if ((bool)check.Invoke(this, new[] { node }))
                    {
                        process.Invoke(this, new[] { node });
                        return node;
                    }
                };
                throw new NotSupportedException($"Node of type {node.NodeType} not supported.");
            }
            
            #region ConstantBools
            private bool ShouldProcessConstantBools(Expression node) => node is ConstantExpression ce && ce.Type == typeof(bool);
            private void ProcessConstantBools(Expression node)
            {
                var mc = node as ConstantExpression;
                QueryParts.Push((bool)mc.Value ? "name = '' or name != ''" : "name = '' and name != ''");
            }
            #endregion 
                
            #region PropertyNotEqual
            private bool ShouldProcessPropertyNotEqual(Expression node) => node.NodeType == ExpressionType.NotEqual && IsBinaryWithParameter(node, nameof(Properties), IndexerPropertyName);
            private void ProcessPropertyNotEqual(Expression node)
            {
                QueryParts.Push(NotToken);
                ProcessPropertyEqual(node);
            }
            #endregion            
            
            #region PropertyEqual
            private bool ShouldProcessPropertyEqual(Expression node) => node.NodeType == ExpressionType.Equal && IsBinaryWithParameter(node, nameof(Properties), IndexerPropertyName);
            private void ProcessPropertyEqual(Expression node)
            {
                var be = node as BinaryExpression;
                (string key, string value) = IsCallWithParameter(be.Left, nameof(Properties), IndexerPropertyName)
                    ? (GetArgumentValue(be.Left, true), GetArgumentValue(be.Right))
                    : (GetArgumentValue(be.Right, true), GetArgumentValue(be.Left));
                QueryParts.Push($"properties has {{key='{key}' and value='{value}'}}");
            }
            #endregion

            #region ParentsContains
            private bool ShouldProcessParentsContains(Expression node) => IsCallWithParameter(node, nameof(Parents), nameof(Enumerable.Contains));
            private void ProcessParentsContains(Expression node)
            {
                var mc = node as MethodCallExpression;
                QueryParts.Push($"'{GetArgumentValue(mc.Arguments[1])}' in parents");
            }
            #endregion

            #region NameStartsWith
            private bool ShouldProcessNameStartsWith(Expression node) => IsCallWithParameter(node, nameof(Name), nameof(String.StartsWith));
            private void ProcessNameStartsWith(Expression node)
            {
                var mc = node as MethodCallExpression;
                QueryParts.Push($"name contains '{GetArgumentValue(mc.Arguments[0])}'");
            }
            #endregion

            #region NameEqual
            private bool ShouldProcessNameEqual(Expression node) => node.NodeType == ExpressionType.Equal && IsBinaryWithParameter(node, nameof(Name));
            private void ProcessNameEqual(Expression node)
            {
                var be = node as BinaryExpression;
                var qArgNode = IsFilterParameter(be.Left, nameof(Name)) ? be.Right : be.Left;
                QueryParts.Push($"name = '{GetArgumentValue(qArgNode)}'");
            }
            #endregion

            #region NameNotEqual
            private bool ShouldProcessNameNotEqual(Expression node) => node.NodeType == ExpressionType.NotEqual && IsBinaryWithParameter(node, nameof(Name));
            private void ProcessNameNotEqual(Expression node)
            {
                var be = node as BinaryExpression;
                var qArgNode = IsFilterParameter(be.Left, nameof(Name)) ? be.Right : be.Left;
                QueryParts.Push($"name != '{GetArgumentValue(qArgNode)}'");
            }
            #endregion

            private static string GetArgumentValue(Expression node, bool doNotInvokeCalls = false)
            {
                switch (node)
                {
                    case ConstantExpression nswConst:
                        return nswConst?.Value?.ToString();
                    case MethodCallExpression nswCall:
                        return doNotInvokeCalls ? GetArgumentValue(nswCall.Arguments[0]) : TryEvalAsString(nswCall);
                    case MemberExpression memExp:
                        return TryEvalAsString(memExp);
                    default:
                        try
                        {
                            return TryEvalAsString(node);
                        }
                        catch
                        {
                            throw new NotSupportedException($"Node {node.ToString()} not supported as argument value.");
                        }
                }
            }

            private static string TryEvalAsString(Expression node) => Expression.Lambda(node).Compile().DynamicInvoke()?.ToString();
            //matches direct valiable, i.e. x.prop 
            private static bool IsFilterParameter(Expression node, string name) => node is MemberExpression maExp && maExp.Member.Name == name && maExp.Expression is ParameterExpression mpExp && mpExp.Type == typeof(GoogleDriveFileListQuery);
            //matches method call with one of parameters is x.prop or x.prop is used as paramter to method with 1 or 2 params (string.StartsWith / Enumrable.Contains)
            private static bool IsCallWithParameter(Expression node, string name, string methodName) => node is MethodCallExpression mcExp && mcExp.Method.Name == methodName && IsFilterParameter(mcExp.Object ?? mcExp.Arguments[0], name);
            //matches binary with one of parameters is x.prop or x.prop is used as paramter to method with 1 or 2 params (string.StartsWith / Enumrable.Contains)
            private static bool IsBinaryWithParameter(Expression node, string name, string methodName = null) => node is BinaryExpression binExp && (
                string.IsNullOrEmpty(methodName)
                ? (IsFilterParameter(binExp.Left, name) || IsFilterParameter(binExp.Right, name))
                : (IsCallWithParameter(binExp.Left, name, methodName) || IsCallWithParameter(binExp.Right, name, methodName)));

        }
    }
    
}
