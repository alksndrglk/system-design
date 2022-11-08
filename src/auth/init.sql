CREATE USER auth_user WITH PASSWORD 'hackme';
DROP DATABASE IF EXISTS auth;
CREATE DATABASE auth;
ALTER DATABASE auth OWNER TO auth_user;
GRANT ALL PRIVILEGES ON DATABASE auth TO auth_user;

CREATE TABLE auth_users (
  id serial PRIMARY KEY,
  email varchar(256) NOT NULL UNIQUE,
  password varchar(256) NOT NULL
);

INSERT INTO auth_users(email, password) VALUES ('admin@admin.com', 'd74ff0ee8da3b9806b18c877dbf29bbde50b5bd8e4dad7a3a725000feb82e8f1');
