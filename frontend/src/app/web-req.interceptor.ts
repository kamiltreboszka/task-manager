import { HttpHandler, HttpInterceptor, HttpRequest, HttpErrorResponse } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { empty, Observable, Subject, throwError } from 'rxjs';
import { catchError, switchMap, tap } from 'rxjs/operators';
import { AuthService } from './auth.service';

@Injectable({
  providedIn: 'root'
})
export class WebReqInterceptor implements HttpInterceptor{

  constructor(private authService: AuthService) { }

  refreshingAccessToken: boolean;

  accessTokenRefreshed: Subject<any> = new Subject();

  intercept(request: HttpRequest<any>, next: HttpHandler): Observable<any>{
    //podtrzymanie zapytania
    request = this.addAuthHeader(request);

    //wywołanie next() i podtrzymanie odpowiedzi
    return next.handle(request).pipe(
      catchError((error: HttpErrorResponse) => {
        console.log(error);

        if(error.status == 401) {
          //wystapienie błedu 401 w momencie, kiedy nie mamy autoryzacji

          //odswiezenie tokenu dostepu
          return this.refreshAccessToken()
            .pipe(
              switchMap(() => {
                request = this.addAuthHeader(request);
                return next.handle(request);
              }),
              catchError((err: any) => {
                console.log(err);
                this.authService.logout();
                return empty();
              })
          )
        }

        return throwError(error);
      })
    )
  }

  refreshAccessToken() {
    if (this.refreshingAccessToken) {
      return new Observable(observer => {
        this.accessTokenRefreshed.subscribe(() => {
          // ten fragment kodu uruchamia się kiedy token zostanie odswieżony
          observer.next();
          observer.complete();
        })
      })
    } else {
    this.refreshingAccessToken = true;
      //wywołanie metody w auth service w celu wysłania zapytania, żeby odswieżyć access token
      return this.authService.getNewAccessToken().pipe(
        tap(()=>{
          console.log("Odświeżono token dostępu!");
          this.refreshingAccessToken = false;
          this.accessTokenRefreshed.next();
        })
      )
    }
  }

  addAuthHeader(request: HttpRequest<any>){
    //pobranie tokenu dostepu
    const token = this.authService.getAccessToken();

    if(token)
    {
      //dołaczenie tokenu dostepu do nagłowka zapytania
      return request.clone({
        setHeaders: {
          'x-access-token': token
        }
      })
    }
    return request;
  }


  
}
