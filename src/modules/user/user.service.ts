import { Injectable } from "@nestjs/common";
import { CreateUserDto } from "./dto/create-user.dto";
import { UpdateUserDto } from "./dto/update-user.dto";
import { InjectRepository } from "@nestjs/typeorm";
import { UserEntity } from "./entities/user.entity";
import { Repository } from "typeorm";
import { Cron, CronExpression } from "@nestjs/schedule";

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(UserEntity) private userRepository: Repository<UserEntity>
  ) {}
  async create(createUserDto: CreateUserDto) {
    const { first_name, last_name } = createUserDto;
    const newUser = this.userRepository.create({
      first_name,
      last_name,
    });

    await this.userRepository.save(newUser);
    return {
      message: "user created successfully",
    };
  }

  async findAll() {
    const users = await this.userRepository.find({});
    return users;
  }

  @Cron(CronExpression.EVERY_WEEK)
  async handleCron() {
    const users = await this.userRepository.find({
      where: {
        mobile_verify: false,
      },
    });

    if (users.length >= 1) {
      console.log("deleting users");
      await this.userRepository.remove(users);
    } else {
      console.log("all users are verified their mobile number");
    }
  }
}
