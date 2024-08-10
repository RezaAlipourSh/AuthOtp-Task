import { registerAs } from "@nestjs/config";

export enum ConfigKeys {
  App = "App",
  Db = "Db",
  Jwt = "Jwt",
}

const AppConfig = registerAs(ConfigKeys.App, () => {
  return {
    port: 3000,
  };
});

const JwtConfig = registerAs(ConfigKeys.Jwt, () => ({
  accessTokenSecret: "d56a3eeed73539c7b0de752f02d801f2d9345fa2",
  refreshTokenSecret: "dc479bb02d0b63803793a2114d8ffcaa188cd787",
}));

const DbConfig = registerAs(ConfigKeys.Db, () => ({
  port: 5432,
  host: "localhost",
  username: "postgres",
  password: "a1870502930@",
  database: "auth-otp",
}));

export const configurations = [AppConfig, DbConfig, JwtConfig];
