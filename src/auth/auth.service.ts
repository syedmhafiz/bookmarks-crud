import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class AuthService {
    constructor(private prismaService: PrismaService) {}

    signUp() {
        return { success: true, msg: 'I have signed up' };
    }

    signIn() {
        return { success: true, msg: 'I have signed in' };
    }
}
