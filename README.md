# Enhanced-Authentication-API
The code is present in the master branch.
Hi this is Parth Ulhas Vaidya and this is my readme file for the given assignment.
Install SQlite 3 db to view the userdata.db table in UI form if required
The main folder consist of node_modules, app.js, database.js, package-lock.json and userdata.db

Here are the steps to run the assignment.

1) Open terminal and write npm init -y      [This initializes the node modules]
2) Next step is to initialize npm install express sqlite3 body-parser bcrypt multer
3) Next step is to initialze npm install knex sqlite3
3) Once done run->  node ./database.js     [to check the database data] 
4) Then run -> node ./app.js which should show the message as Server is running.

5) 

Since it a backend project it is hosted on vercel app: https://enhanced-authentication-api.vercel.app/

After the initialization here are the steps to test the data using Postman
1) To register use the endpoint as http://localhost:3000/register
2) Then insert the data in raw format for example 
{
      "name": "Abcde fgh",
    "phoneNumber": "123456799",
	"email" : "abc@gmail.com",
    "password" : "password1564"
}

3) To use the login endpoint use http://localhost:3000/login 
4) Then insert the data in raw format 
{
"phoneNumber": "123456799",
"password" : "password1456"
5) use the profile endpoint use http://localhost:3000/profile with the JWT token as authenticator(One is PUT and other is GET as per assignment requirements)
6) logout endpoint http://localhost:3000/logout
7) http://localhost:3000/users with jwt you can get the users which are admin and public/private .

NOTE: This may not be the perfect representation and can have some errors but i assure the logic used is correct and it is a request it can be taken into consideration
