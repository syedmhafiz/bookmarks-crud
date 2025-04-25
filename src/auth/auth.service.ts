import { ForbiddenException, Injectable, InternalServerErrorException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService, private jwt: JwtService, private config: ConfigService) {}

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

            return this.signToken(user?.id, user?.email);
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

        return this.signToken(user?.id, user?.email);
    }

    async signToken(userId: number, email: string): Promise<{ access_token: string }> {
        const payload = {
            sub: userId,
            email,
        }

        const token = await this.jwt.signAsync(payload, {
            expiresIn: '60m',
            secret: this.config.get('JWT_SECRET'),
        });

        return {
            access_token: token
        };
    }
}
