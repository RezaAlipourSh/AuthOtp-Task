import { IsEmail, IsMobilePhone, IsString, Length } from "class-validator";
import { ConfirmPassword } from "src/common/decorators/password.decorator";

export class SignupDto {
  @IsString()
  first_name: string;
  @IsString()
  last_name: string;
  @IsMobilePhone("fa-IR", {}, { message: "must be iranian number" })
  mobile: string;

  @IsString()
  @IsEmail(
    { host_whitelist: ["gmail.com", "yahoo.com", "outlook.com"] },
    { message: "your email is incorrect" }
  )
  email: string;
  @IsString()
  @Length(6, 20, { message: "bin 6 ta 20" })
  password: string;
  @IsString()
  @ConfirmPassword("password")
  confirm_password: string;
}

export class LoginDto {
  @IsString()
  @IsEmail({}, { message: "your email is incorrect" })
  email: string;
  @IsString()
  @Length(6, 20, { message: "bin 6 ta 20" })
  password: string;
}
