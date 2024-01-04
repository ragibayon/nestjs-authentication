import { Injectable } from '@nestjs/common';
import { User } from './schema/user.schema';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { RegisterUserDto } from '../auth/dto/register-user.dto';

@Injectable()
export class UsersRepository {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
  ) {}

  async create(registerUserDto: RegisterUserDto) {
    return await this.userModel.create(registerUserDto);
  }

  async findById(id: string) {
    return await this.userModel.findById(id);
  }

  async findOne(filter: object, populateField: string = '') {
    return await this.userModel.findOne(filter).populate(populateField);
  }

  async findOneAndUpdate(filter: object, updateFields: object) {
    return await this.userModel.findOneAndUpdate(filter, updateFields);
  }

  async findByIdAndUpdate(id: string, updateFields: object) {
    return await this.userModel.findByIdAndUpdate(id, updateFields);
  }

  async find(filter: object = {}, populateField: string = '') {
    return await this.userModel.find(filter).populate(populateField);
  }
}
