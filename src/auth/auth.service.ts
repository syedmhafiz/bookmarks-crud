import { ForbiddenException, Injectable, InternalServerErrorException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService) {}

    async signUp(dto: AuthDto) {
        try {
          // Check if user already exists
            const existingUser = await this.prisma.user.findUnique({
                where: { email: dto.email },
            });
    
            if (existingUser) throw new ForbiddenException('Email is already taken');

            // Hash password
            const hash = await argon.hash(dto.password);
        
            // Create new user
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash,
                }
            });

            delete user.hash;
            return user;
        } catch (error) {
            if (error instanceof ForbiddenException) throw error;
            throw new InternalServerErrorException('Failed to create user');
        }
      }

    async logIn(dto: AuthDto) {
        // find the user
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto?.email,
            }
        });
        if (!user) throw new ForbiddenException(
            'Credentials incorrect, no user found'
        );
        
        // compare password, if not correct throw excep
        const passwordMatches = await argon.verify(user?.hash, dto?.password);
        if (!passwordMatches) throw new ForbiddenException(
            'Incorrect password, try again'
        );

        delete user.hash;
        return user;
    }
}
