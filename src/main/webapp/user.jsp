<%@ page import="java.sql.*,com.cryptdac.util.*" contentType="text/html;charset=UTF-8" %>
<% if (!"user".equals(session.getAttribute("role"))) { response.sendRedirect("index.jsp"); return; }
   int uid = (Integer) session.getAttribute("id"); %>
<%@ include file="header.jspf" %>
<% try (Connection c = DB.get()) { %>
<h2>Files in the cloud</h2><div class="card"><table><tr><th>File</th><th>Access</th><th></th></tr>
<% try (PreparedStatement p = c.prepareStatement(
   "SELECT f.file_id,f.file_name," +
   "(SELECT COUNT(*) FROM access_policies a WHERE a.file_id=f.file_id AND a.allowed_user_id=? AND a.active=1 AND (a.expiration_time IS NULL OR a.expiration_time>NOW())) AS ok," +
   "(SELECT COUNT(*) FROM access_requests q WHERE q.file_id=f.file_id AND q.user_id=? AND q.status='pending') AS pend " +
   "FROM files f WHERE f.is_deleted=0 ORDER BY f.file_id DESC")) {
   p.setInt(1, uid); p.setInt(2, uid);
   try (ResultSet r = p.executeQuery()) { while (r.next()) { %>
<tr><td><%= Html.esc(r.getString(2)) %></td>
<% if (r.getInt(3) > 0) { %><td>Granted</td><td><a href="user?file=<%= r.getInt(1) %>">Download and decrypt</a></td>
<% } else if (r.getInt(4) > 0) { %><td>Request pending</td><td></td>
<% } else { %><td>No access</td><td><form class="inline" method="post" action="user"><input type="hidden" name="file" value="<%= r.getInt(1) %>"><button>Request access</button></form></td><% } %></tr>
<% } } } %></table></div>
<% } catch (Exception e) { %><div class="msg"><%= Html.esc(e.getMessage()) %></div><% } %>
<%@ include file="footer.jspf" %>
