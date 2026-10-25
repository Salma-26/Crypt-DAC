<%@ page import="java.sql.*,com.cryptdac.util.*" contentType="text/html;charset=UTF-8" %>
<% if (!"cloud".equals(session.getAttribute("role"))) { response.sendRedirect("index.jsp"); return; } %>
<%@ include file="header.jspf" %>
<% try (Connection c = DB.get()) {
   String[][] t = {{"owner","data_owners","owner_id","owner_name"},{"user","end_users","user_id","user_name"}};
   for (String[] x : t) { %>
<h2>Pending <%= x[0] %> accounts</h2><div class="card"><table><tr><th>ID</th><th>Name</th><th>Email</th><th>Status</th><th></th></tr>
<% try (PreparedStatement p = c.prepareStatement("SELECT "+x[2]+","+x[3]+",email,status FROM "+x[1]+" ORDER BY status DESC,"+x[2]);
        ResultSet r = p.executeQuery()) { while (r.next()) { %>
<tr><td><%= r.getInt(1) %></td><td><%= Html.esc(r.getString(2)) %></td><td><%= Html.esc(r.getString(3)) %></td><td><%= Html.esc(r.getString(4)) %></td>
<td><% if (!"authorized".equals(r.getString(4))) { %><form class="inline" method="post" action="cloud"><input type="hidden" name="role" value="<%= x[0] %>"><input type="hidden" name="id" value="<%= r.getInt(1) %>"><button>Authorize</button></form><% } %></td></tr>
<% } } %></table></div>
<% } %>
<h2>Stored files (ciphertext only)</h2><div class="card"><table><tr><th>ID</th><th>Name</th><th>Owner</th><th>Layers</th><th>Chunks</th></tr>
<% try (PreparedStatement p = c.prepareStatement("SELECT f.file_id,f.file_name,f.owner_id,f.layer_count,(SELECT COUNT(*) FROM file_chunks k WHERE k.file_id=f.file_id) FROM files f WHERE f.is_deleted=0");
        ResultSet r = p.executeQuery()) { while (r.next()) { %>
<tr><td><%= r.getInt(1) %></td><td><%= Html.esc(r.getString(2)) %></td><td><%= r.getInt(3) %></td><td><%= r.getInt(4) %></td><td><%= r.getInt(5) %></td></tr>
<% } } %></table></div>
<h2>Transactions, time delay and throughput</h2><div class="card"><table><tr><th>Time</th><th>Action</th><th>File</th><th>Detail</th><th>Delay (ms)</th><th>Throughput (KB/s)</th></tr>
<% try (PreparedStatement p = c.prepareStatement("SELECT created_at,action_type,file_id,action_message,elapsed_ms,bytes_processed FROM audit_logs ORDER BY log_id DESC LIMIT 50");
        ResultSet r = p.executeQuery()) { while (r.next()) { long ms = r.getLong(5), b = r.getLong(6); double kbs = ms > 0 ? (b / 1024.0) / (ms / 1000.0) : 0; %>
<tr><td><%= r.getTimestamp(1) %></td><td><%= Html.esc(r.getString(2)) %></td><td><%= r.getInt(3) %></td><td><%= Html.esc(r.getString(4)) %></td>
<td><span class="bar" style="width:<%= Math.min(200, ms) %>px"></span> <%= ms %></td><td><%= String.format("%.1f", kbs) %></td></tr>
<% } } %></table></div>
<% } catch (Exception e) { %><div class="msg"><%= Html.esc(e.getMessage()) %></div><% } %>
<%@ include file="footer.jspf" %>
