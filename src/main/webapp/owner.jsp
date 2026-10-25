<%@ page import="java.sql.*,com.cryptdac.util.*" contentType="text/html;charset=UTF-8" %>
<% if (!"owner".equals(session.getAttribute("role"))) { response.sendRedirect("index.jsp"); return; }
   int oid = (Integer) session.getAttribute("id"); %>
<%@ include file="header.jspf" %>
<% try (Connection c = DB.get()) {
   int swept = FileService.sweepExpired(c, oid, CryptoUtil.privFrom((byte[]) session.getAttribute("priv")), FileService.ownerPub(c, oid));
   if (swept > 0) { %><div class="msg"><%= swept %> expired permission(s) revoked automatically.</div><% } %>
<h2>Upload a file</h2><div class="card"><form method="post" action="owner" enctype="multipart/form-data">
<input type="hidden" name="action" value="upload"><input type="file" name="file" required> <button>Encrypt and upload</button></form></div>

<h2>Pending access requests</h2><div class="card"><table><tr><th>User</th><th>File</th><th>Grant</th></tr>
<% try (PreparedStatement p = c.prepareStatement("SELECT q.user_id,u.user_name,q.file_id,f.file_name FROM access_requests q JOIN end_users u ON q.user_id=u.user_id JOIN files f ON q.file_id=f.file_id WHERE f.owner_id=? AND q.status='pending' AND f.is_deleted=0")) {
   p.setInt(1, oid); try (ResultSet r = p.executeQuery()) { while (r.next()) { %>
<tr><td><%= Html.esc(r.getString(2)) %></td><td><%= Html.esc(r.getString(4)) %></td><td>
<form class="inline" method="post" action="owner"><input type="hidden" name="action" value="grant"><input type="hidden" name="file" value="<%= r.getInt(3) %>"><input type="hidden" name="user" value="<%= r.getInt(1) %>">
<select name="privilege"><option>read</option><option>write</option></select><input name="hours" type="number" min="0" value="24" title="Hours until expiry, 0 for never" style="width:80px"><button>Approve</button></form></td></tr>
<% } } } %></table></div>

<h2>Your files</h2>
<% try (PreparedStatement p = c.prepareStatement("SELECT file_id,file_name,layer_count,checksum FROM files WHERE owner_id=? AND is_deleted=0 ORDER BY file_id DESC")) {
   p.setInt(1, oid); try (ResultSet r = p.executeQuery()) { while (r.next()) { int fid = r.getInt(1); %>
<div class="card"><strong><%= Html.esc(r.getString(2)) %></strong> <span class="muted">file <%= fid %>, onion layers <%= r.getInt(3) %>/<%= FileService.MAX_LAYERS %>
<%= r.getInt(3) >= FileService.MAX_LAYERS ? " (limit reached: update the file to clear layers)" : "" %></span>
<p>
<form class="inline" method="post" action="owner"><input type="hidden" name="action" value="verify"><input type="hidden" name="file" value="<%= fid %>"><button>Verify</button></form>
<form class="inline" method="post" action="owner"><input type="hidden" name="action" value="delete"><input type="hidden" name="file" value="<%= fid %>"><button class="danger">Delete</button></form>
<form class="inline" method="post" action="owner" enctype="multipart/form-data"><input type="hidden" name="action" value="update"><input type="hidden" name="file" value="<%= fid %>"><input type="file" name="newfile" required><button>Update file</button></form></p>
<form class="inline" method="post" action="owner"><input type="hidden" name="action" value="grant"><input type="hidden" name="file" value="<%= fid %>">
<select name="user" required><option value="">Choose user</option>
<% try (PreparedStatement q = c.prepareStatement("SELECT user_id,user_name FROM end_users WHERE status='authorized'"); ResultSet u = q.executeQuery()) { while (u.next()) { %>
<option value="<%= u.getInt(1) %>"><%= Html.esc(u.getString(2)) %></option><% } } %></select>
<select name="privilege"><option>read</option><option>write</option></select>
<input name="hours" type="number" min="0" value="24" title="Hours until expiry, 0 for never" style="width:80px"><button>Grant access</button></form>
<table><tr><th>User</th><th>Privilege</th><th>Expires</th><th></th></tr>
<% try (PreparedStatement q = c.prepareStatement("SELECT p.policy_id,u.user_name,p.privilege,p.expiration_time FROM access_policies p JOIN end_users u ON p.allowed_user_id=u.user_id WHERE p.file_id=? AND p.active=1")) {
   q.setInt(1, fid); try (ResultSet u = q.executeQuery()) { while (u.next()) { %>
<tr><td><%= Html.esc(u.getString(2)) %></td><td><%= Html.esc(u.getString(3)) %></td><td><%= u.getTimestamp(4) == null ? "never" : u.getTimestamp(4) %></td>
<td><form class="inline" method="post" action="owner"><input type="hidden" name="action" value="revoke"><input type="hidden" name="policy" value="<%= u.getInt(1) %>"><button class="danger">Revoke</button></form></td></tr>
<% } } } %></table></div>
<% } } } } catch (Exception e) { %><div class="msg"><%= Html.esc(e.getMessage()) %></div><% } %>
<%@ include file="footer.jspf" %>
