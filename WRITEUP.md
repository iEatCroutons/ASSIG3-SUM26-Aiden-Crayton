Fix 1: const sql = SELECT id, username FROM users  + WHERE username = '${username}' AND password = '${password}';

Was vulnerable because it took the user's input and directly concatenates it into the SQL statement. The exploit submits the credentials: "' OR 1-1 --" as the username and anything as the password. The payload closes the original string, injected OR 1=1, and uses -- to comment the remainder of the query, including the password comparison. Since OR 1=1 always evaluates to true, the database returned a valid user record. The pasword section of the query was commented out, so a valid password was not needed. This ends up working as a valid login.

To fix, we use parametrized placeholders instead of directly using user input. We change WHERE username = '${username}' AND password = '${password}'; ==> WHERE username = ? AND password = ?; and user = get(sql); ==> user = get(sql, [username, password]);

Using ? as a placeholder separates the SQL statement from the user input. The database then treats the values in [username, password] as just data rather than executable SQL, so special characters don't change the structure or logic.

This fix prevents SQL injection at the login query, but SQL queries anywhere else in the application might still be vulnerable if they concatenate user input instead of parametrizing.




Fix 2: const sql = SELECT id, title, species, location FROM listings  + WHERE title LIKE '%${q}%' OR species LIKE '%${q}%'  + ORDER BY ${sort};

Was vulnerable because the search term was concatenated directly into the query, so an attacker could inject SQL instead of an expected string. This made it possible to add SQL statements, such as UNION SELECT, to retrieve data from database tables. The exploit uses the input: ' UNION SELECT 1, username, password, 4 FROM users -- This payload closes the LIKE string, appends UNION SELECT with four columns to match the original query, selected the username and password fields, then used -- to comment the rest of the query. This caused the database to combine the normal search results along with the confidential usernames and passwords of users.

To fix, we parametrize user q value with placeholders and validate by using safeSort instead of sort. The code becomes: const sql = SELECT id, title, species, location FROM listings  + WHERE title LIKE ? OR species LIKE ?  + ORDER BY ${safeSort};

let rows = [];
let error = null;
try {
  rows = all(sql, [`%${q}%`, `%${q}%`]);
} catch (e) {
  error = e.message;
}
Using placeholders letsd the aplication to read the input as data rather than an SQL and safeSort to only allow title, species, or location.

This fix prevents SQL injection at the search query, but SQL queries anywhere else in the application might still be vulnerable if they concatenate user input instead of parametrizing.




Fix 3: const heading = <h1>Search</h1><p class="note">Showing results for “${q}”</p>; const bodyErr = error ? <p class="error">Query error: ${error}</p> : '';

Was vulnerable because the application didn't sanitize the search term, to the browser interpretted the HTML as actual content. This allowed the attacker to inject JavaScript elements to trigger a response, which executes an attack whenever a victim loads the page. The exploit uses the input: '<img src=x onerror=alert('Hello Bozo')>' The payload creats an image element with an invalid source, which causes an error that triggers the onerror element of the payload.

To fix, we make th application HTML-encoide all untrusted values before inserting them. The code becomes: function escapeHtml(value) { return String(value) .replaceAll('&', '&') .replaceAll('<', '<') .replaceAll('>', '>') .replaceAll('"', '"') .replaceAll("'", '''); }

const heading = `<h1>Search</h1><p class="note">Showing results for “${escapeHtml(q)}”</p>`;

const bodyErr = error ? `<p class="error">Query error: ${escapeHtml(error)}</p>` : '';
The new function converts special characters into safe HTML entities to prevent the browser from interpretting user input as HTML elements.

This prevents XSS in places where escapeHTML() is implemented, but does not protect other parts that still use unencoded user input.




Fix 4:

${c.body}

— ${c.author}, ${c.created_at}

Was vulnerable because the stored comment body was placed as raw HTML, so an atacker could enter a comment with malicious markup. This markup would execute anytime anyone opened the page with the comment. The payload was the comment: <img src=x onerror=alert('xss_MARKER')> The payload creats an image element with an invalid source, which causes an error that triggers the onerror element of the payload.

To fix, we make th application HTML-encoide all untrusted values before displaying them in the comments. We can use the escapeHTML function previously created. The code becomes:

${escapeHtml(c.body)}

— ${escapeHtml(c.author)}, ${escapeHtml(c.created_at)}

The function converts special characters into safe HTML entities to prevent the browser from interpretting user input as HTML elements.

This prevents XSS in places where escapeHTML() is implemented, but does not protect other parts that still use unencoded user input.




Fix 5 Part A (No exploit file): res.setHeader('Set-Cookie', sid=${token}; Path=/);

Was vulnerable because the cookie was missing protections, such as HTTPOnly and SameSite. Without these protections, the session cookie is vulnerable to Javascript accessing the cookie through document.cookie and CSRF attacks if the browser attached the cookie to certain cross-site requests.

To fix, we add HttpOnly and SameSite=Lax to the login and logout session cookies:

  res.setHeader('Set-Cookie', 'sid=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax');
  res.setHeader('Set-Cookie', `sid=${token}; Path=/; HttpOnly; SameSite=Lax`);
HttpOnly prevents client-side Javascript from accessing session cookies and SameSite=Lax limits the browser sending cokies during cross-site requests.

This protects the session token from certain attacks, but does not protect against XSS or server-side session system attacks.


Fix 5 Part B (No exploit file): The application did not set a Content-Security Policy header on responses. Without this the browser had no restrictions that prevent injected scripts or event handlers if an attack were successful. To fix, a middleware function was added near the top of the apps code so every response contains a CSP header:

  app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'");
  next();
  });
This tells the browser to only load scripts and styles from the app's own files and blocks inline JavaScript. This way, even if an attacker is able to inject HTML, the browser itself has additional restrictions.

The CSP provides an added layer of defense, but cannot replace proper input validation and encoding.
