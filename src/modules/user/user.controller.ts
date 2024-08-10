import {
  Controller,
  Get,
  Post,
  Body,
  UseGuards,
  Req,
  ForbiddenException,
} from "@nestjs/common";
import { UserService } from "./user.service";
import { CreateUserDto } from "./dto/create-user.dto";
import { AuthGuard } from "../auth/guards/auth.guard";
import { Request } from "express";

@Controller("user")
@UseGuards(AuthGuard)
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.userService.create(createUserDto);
  }

  @Get()
  findAll(@Req() request: Request) {
    const role = request.user.role;
    if (role !== "admin") {
      throw new ForbiddenException("you don't have access for this request");
    }

    return this.userService.findAll();
  }
  @Get("/profile")
  profile(@Req() request: Request) {
    return request.user;
  }
}
