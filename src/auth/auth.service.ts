import { HttpCode, HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { FirebaseService } from 'src/firebase/firebase.service';
import { User } from 'src/models/user.model';
import {
  AuthError,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  UserCredential,
} from 'firebase/auth';
import {
  setDoc,
  DocumentReference,
  doc,
  getDoc,
  DocumentSnapshot,
  DocumentData,
} from 'firebase/firestore';

@Injectable()
export class AuthService {
  constructor(private firebaseService: FirebaseService) {}

  public async login(
    email: string,
    password: string,
  ): Promise<Omit<User, 'password'>> {
    try {
      const userCredential: UserCredential = await signInWithEmailAndPassword(
        this.firebaseService.auth,
        email,
        password,
      );

      if (userCredential) {
        const id: string = userCredential.user.uid;
        const docRef: DocumentReference = doc(
          this.firebaseService.usersCollection,
          id,
        );

        const snapshot: DocumentSnapshot<DocumentData> = await getDoc(docRef);
        const loggedUser: User = {
          ...snapshot.data(),
          id: snapshot.id,
        } as User;

        delete loggedUser.password;
        console.log(loggedUser.name);
        
        return loggedUser;
      }
    } catch (error: unknown) {
      this.handleExceptions(error);
    }
  }

  public async register(body: Omit<User, 'id'>): Promise<string> {
    try {
      const userCredential: UserCredential =
        await createUserWithEmailAndPassword(
          this.firebaseService.auth,
          body.email,
          body.password,
        );

      if (userCredential) {
        const id: string = userCredential.user.uid;
        const docRef: DocumentReference = doc(
          this.firebaseService.usersCollection,
          id,
        );
        await setDoc(docRef, body);
        return `USER CREATED`;        
      }
    } catch (error: unknown) {
      this.handleExceptions(error);     
    }
  }



  public handleExceptions(error: unknown){
    const firebaseAuthError = error as AuthError;

    console.log(`[FIREBASE AUTH ERROR CODE]: ${firebaseAuthError.code}`);

    if (firebaseAuthError.code === 'auth/email-already-in-use') {
      throw new HttpException('Email already exists.', HttpStatus.CONFLICT);
    }

    if (firebaseAuthError.code === 'auth/wrong-password') {
      throw new HttpException(
        'Email or password incorrect.',
        HttpStatus.FORBIDDEN,
      );
    }

    if (firebaseAuthError.code === 'auth/user-not-found') {
      throw new HttpException('Email not found.', HttpStatus.NOT_FOUND);
    }
  }
}
