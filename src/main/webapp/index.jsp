<%@ page contentType="text/html;charset=UTF-8" %>
<%@ include file="header.jspf" %>
<p>Files stay encrypted in the cloud. Revoking access adds a new encryption layer in the cloud, so removed users are locked out at once.</p>
<div class="grid">
<div class="card"><h2>Sign in</h2>
<form method="post" action="auth"><input type="hidden" name="action" value="login">
<p><select name="role"><option value="owner">Data owner</option><option value="user">End user</option><option value="cloud">Cloud server</option></select></p>
<p><input name="name" placeholder="Name" required></p>
<p><input name="password" type="password" placeholder="Password" required></p>
<button>Sign in</button></form></div>
<div class="card"><h2>Register</h2>
<form method="post" action="auth"><input type="hidden" name="action" value="register">
<p><select name="role"><option value="owner">Data owner</option><option value="user">End user</option></select></p>
<p><input name="name" placeholder="Name" required></p>
<p><input name="email" type="email" placeholder="Email" required></p>
<p><input name="password" type="password" placeholder="Password (6+ characters)" minlength="6" required></p>
<button>Create account</button></form>
<p class="muted">The cloud server must authorize new accounts before they can sign in.</p></div>
</div>
<%@ include file="footer.jspf" %>
