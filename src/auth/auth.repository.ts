import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Auth } from './schema/auth.schema';

@Injectable()
export class AuthRepository {
  constructor(
    @InjectModel(Auth.name) private readonly authModel: Model<Auth>,
  ) {}

  async create(createAuthDto: object) {
    return await this.authModel.create(createAuthDto);
  }

  async findOne(filter: object, populateFiled: string = '') {
    return await this.authModel.findOne(filter).populate(populateFiled);
  }

  async findById(id: string) {
    return await this.authModel.findById(id);
  }

  async findByIdAndUpdate(id: string, updateObj: object) {
    return await this.authModel.findByIdAndUpdate(id, updateObj);
  }
  async findOneAndUpdate(filter: object, updateObj: object) {
    return await this.authModel.findOneAndUpdate(filter, updateObj);
  }
}
