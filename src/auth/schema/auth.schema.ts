import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { HydratedDocument, mongo } from 'mongoose';
import { User } from '../../user/schema/user.schema';

@Schema({ timestamps: true })
export class Auth {
  @Prop()
  refreshToken: string;
  @Prop()
  emailVerificationToken: string;
  @Prop()
  passwordResetToken: string;

  // auth belongs to which user
  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'user', unique: true })
  user: User;
}

// export interface
export interface IAuth extends HydratedDocument<Auth> {}

// export schema for model
export const authSchema = SchemaFactory.createForClass(Auth);
