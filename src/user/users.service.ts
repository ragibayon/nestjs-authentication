import { Injectable } from '@nestjs/common';
import { UsersRepository } from './users.repository';
import { RegisterUserDto } from '../auth/dto/register-user.dto';

@Injectable()
export class UsersService {
  constructor(private readonly usersRepository: UsersRepository) {}

  async createUser(registerUserDto: RegisterUserDto) {
    return this.usersRepository.create(registerUserDto);
  }

  async findAllUsers() {
    return this.usersRepository.find();
  }

  async findUserById(userId: string) {
    return this.usersRepository.findById(userId);
  }

  async findUserByEmail(email: string) {
    return this.usersRepository.findOne({ email });
  }

  async updateUserPassword(userId: string, password: string) {
    return await this.usersRepository.findByIdAndUpdate(userId, {
      password: password,
    });
  }
}
