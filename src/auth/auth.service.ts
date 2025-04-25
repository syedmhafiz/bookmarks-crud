import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService) {}

    async signUp(dto: AuthDto) {
        // hash generation
        const hash = await argon.hash(dto?.password);
        // check if user already exists
        const existingUser = await this.prisma.user.findUnique({
            where: {
                email: dto?.email,
            }
        });
        // if exisitng user, throw error if not then create user and return
        if (!existingUser) {
            try {
                const user = await this.prisma.user.create({
                    data: {
                        email: dto?.email,
                        hash,
                    }
                });
                
                delete user.hash;
                return user;
            } catch (error) {
                throw error;
            }
        } else {
            throw new ForbiddenException(
                'Email is already taken',
            )
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
