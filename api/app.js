const express = require('express');
const app = express();

const {mongoose} = require('./db/mongoose');

const bodyParser = require('body-parser');

// Pobranie modeli mongoose
const { List, Task, User } = require('./db/models');

const jwt = require('jsonwebtoken');

// Zaladowanie posredniczace
app.use(bodyParser.json());

// CORS HEADERS MIDDLEWARE
app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS, PUT, PATCH, DELETE");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, x-access-token, x-refresh-token, _id");

    res.header(
        'Access-Control-Expose-Headers',
        'x-access-token, x-refresh-token'
    );

    next();
});

// sprawdzenie czy żadanie ma poprawny token dostępu JWT 
let authenticate = (req, res, next) => {
    let token = req.header('x-access-token');

    // sprawdzenie JWT
    jwt.verify(token, User.getJWTSecret(), (err, decoded) => {
        if (err) {
            // wystapienie błędu
            // jwt jest niepoprawny - * Brak autoryzacji *
            res.status(401).send(err);
        } else {
            // jwt jest poprawny
            req.user_id = decoded._id;
            next();
        }
    });
}

// Verify Refresh Token Middleware (weryfikacja sesji)
let verifySession = (req, res, next) => {
    // bierzemy odswiezony token z naglowka żadania
    let refreshToken = req.header('x-refresh-token');

    // bierzemy id z nagłowka żadania
    let _id = req.header('_id');

    User.findByIdAndToken(_id, refreshToken).then((user) => {
        if (!user) {
            // uzytkownik nie moze byc odnaleziony
            return Promise.reject({
                'error': 'Nie znaleziono uzytkwonika. Upewnij się, że odswiezony token i ID użytkownika są poprawne.'
            });
        }
        // jesli dotrzemy tutaj to uzytkownik zostal znaleziony
        // dlatego odswiezony token istnieje w bazie danych, ale nadal sprawdzamy czy wygasl czy nie

        req.user_id = user._id;
        req.userObject = user;
        req.refreshToken = refreshToken;

        let isSessionValid = false;

        user.sessions.forEach((session) => {
            if (session.token === refreshToken) {
                // sprawdzenie czy sesja wygasła
                if (User.hasRefreshTokenExpired(session.expiresAt) === false) {
                    // odwiezony token nie wygasł
                    isSessionValid = true;
                }
            }
        });

        if (isSessionValid) {
            // sesja jest autoryzowana - wywołanie next() w celu kontynuowania przetwarzania żadania
            next();
        } else {
            // walidacja sesji nie powiodla sie
            return Promise.reject({
                'error': 'Odswiezony token wygasl albo sesja jest niewazna'
            })
        }

    }).catch((e) => {
        res.status(401).send(e);
    })
}

/* ROUTING LIST */
/**
 * GET /lists
 * Cel: Otrzymanie kazdej listy
 */
app.get('/lists', authenticate, (req, res) => {
    //zwrot list z bazy danych, ktore naleza do uzytkownika, który otrzymał autoryzacje
    List.find({
        _userId: req.user_id
    }).then((lists) =>{
        res.send(lists);
    }).catch((e) =>{
        res.send(e);
    });
})

/**
 * POST /lists
 * Cel: Stworzenie listy
 */
 app.post('/lists', authenticate, (req, res) => {
    // Tworzenie nowej listy wraz ze zwrotem dokuemnty listy do uzytkownika(z zawarciem id)
    // Informacje (pola) beda przekazane w zapytaniu json
    let title = req.body.title;

    let newList = new List({
        title,
        _userId: req.user_id
    });
    newList.save().then((listDoc) => {
        // pelen dokument listy jest zwrocony (wraz z id)
        res.send(listDoc);
    })
});

/**
 * PATCH /lists/:id
 * Cel: aktualizacja listy
 */
app.patch('/lists/:id', authenticate, (req, res) => {
    //Aktualizujemy konkretna liste (dokuemnt listy z id z url) o nowe wartosci wyroznione w ciele json zapytania
    List.findOneAndUpdate({_id: req.params.id, _userId: req.user_id}, {
        $set: req.body
    }).then(()=>{
        res.send({ 'message': 'zaktualizowano pomyślnie'});
    });
});

/**
 * DELETE /lists/:id
 * Cel: usuniecie listy
 */
 app.delete('/lists/:id', authenticate, (req, res) => {
    //Usuwamy konkretna liste (dokumentt listy z id z url)
    List.findByIdAndRemove({
        _id: req.params.id,
        _userId: req.user_id
    }).then((removedListDoc)=>{
        res.send(removedListDoc);

        //usuniecie wszystkich zadan z listy
        deleteTasksFromList(removedListDoc._id);
    })
});

/**
 * GET /lists/:listId/task
 * Cel: pobranie wszytskich zadan nalezacych do danej listy
 */
app.get('/lists/:listId/tasks', authenticate, (req, res)=>{
    //Pobranie wszystkich zadan nalezacych do danej listy
    Task.find({
        _listId: req.params.listId
    }).then((tasks)=>{
        res.send(tasks);
    })
});

/*
app.get('/lists/:listId/tasks/:taskId', (req, res)=>{
    Task.findOne({
        _id: req.params.taskId,
        _listId: req.params.listId
    }).then((task)=>{
        res.send(task);
    })
});
*/
/**
 * POST /lists/:listId/task
 * Cel: Utworzenie nowego zadania w wybranej liscie
 */
app.post('/lists/:listId/tasks', authenticate, (req, res)=>{
    //Tworzenie nowego zadania w wybranej lisice

    List.findOne({
        _id: req.params.listId,
        _userId: req.user_id
    }).then((list)=>{
        if(list){
            //lista jest autoryzowany
            //obecna lista z autoryzacja, do ktorej mozna dodawac nowe zadania
            return true;
        }
        //obiekt listy jest nieokreslony
        return false;
    }).then((canCreateTask) =>{
        if(canCreateTask){
            let newTask = new Task({
                title: req.body.title,
                _listId: req.params.listId
            });
            newTask.save().then((newTaskDoc)=>{
                res.send(newTaskDoc);
            })
        } else {
            res.sendStatus(404);
        }
    })

    
})

/**
 * PATCH /lists/:listId/tasks/:taskId
 * Cel: aktualizacja zadania
 */
 app.patch('/lists/:listId/tasks/:taskId', authenticate, (req, res) => {
    //Aktualizujemy konkretne zadanie na liscie (przez id zadania)

    List.findOne({
        _id: req.params.listId,
        _userId: req.user_id    
    }).then((list) =>{
        if(list){
            //lista jest autoryzowany
            //obecna lista z autoryzacja, w ktorej mozna zmieniac zadania
            return true;
        }
        //obiekt listy jest nieokreslony
        return false;
    }).then((canUpdateTasks) =>{
        if(canUpdateTasks){
            //obecny zautoryzowany uzytkownik moze wprowadzac aktualizacje do zadan
            Task.findOneAndUpdate({
                _id: req.params.taskId, 
                _listId: req.params.listId
            },  {
                    $set: req.body
                }
            ).then(()=>{
                res.send({message: 'Pomyslnie zaktualizowano'});
            })
        } else {
            res.sendStatus(404);
        }
    })

    
});

/**
 * DELETE /lists/:listId/tasks/:taskId
 * Cel: usuniecie zadania
 */
 app.delete('/lists/:listId/tasks/:taskId', authenticate, (req, res) => {
    //Usuwamy konkretne zadanie (przez id zadania)

    List.findOne({
        _id: req.params.listId,
        _userId: req.user_id    
    }).then((list) =>{
        if(list){
            //lista jest autoryzowany
            //obecna lista z autoryzacja, w ktorej mozna zmieniac zadania
            return true;
        }
        //obiekt listy jest nieokreslony
        return false;
    }).then((canDeleteTasks) =>{
        if(canDeleteTasks){
            Task.findByIdAndRemove({
                _id: req.params.taskId,
                _listId: req.params.listId
            }).then((removedTaskDoc)=>{
                res.send(removedTaskDoc);
            })
        } else{
            res.sendStatus(404);
        }
    });
    
});

/* USER ROUTES */
/**
 * POST /users
 * Cel: Utworzenie konta
 */
 app.post('/users', (req, res) => {
    // Logowanie uzytkownika

    let body = req.body;
    let newUser = new User(body);

    newUser.save().then(() => {
        return newUser.createSession();
    }).then((refreshToken) => {
        // Sesja utworzona pomyslnie - refreshToken zwrocony.
        // generowanie tokenu dostepu dla uzytkownika

        return newUser.generateAccessAuthToken().then((accessToken) => {
            // token dostepu wygenerowany pomyslnie, zwrocenie obiektu zawierajacy token autoryzacyjny
            return { accessToken, refreshToken }
        });
    }).then((authTokens) => {
        // zbudowanie i wyslanie zapytania do uzytkownika z tokenem w naglowku i obiektem w body
        res
            .header('x-refresh-token', authTokens.refreshToken)
            .header('x-access-token', authTokens.accessToken)
            .send(newUser);
    }).catch((e) => {
        res.status(400).send(e);
    })
})


/**
 * POST /users/login
 * Cel: Login
 */
app.post('/users/login', (req, res) => {
    let email = req.body.email;
    let password = req.body.password;

    User.findByCredentials(email, password).then((user) => {
        return user.createSession().then((refreshToken) => {
            // Sesja utworzona pomyslnie - refreshToken zwrocony.
            // generowanie tokenu dostepu dla uzytkownika

            return user.generateAccessAuthToken().then((accessToken) => {
                // token dostepu wygenerowany pomyslnie, zwrocenie obiektu zawierajacy token autoryzacyjny
                return { accessToken, refreshToken }
            });
        }).then((authTokens) => {
            // zbudowanie i wyslanie zapytania do uzytkownika z tokenem w naglowku i obiektem w body
            res
                .header('x-refresh-token', authTokens.refreshToken)
                .header('x-access-token', authTokens.accessToken)
                .send(user);
        })
    }).catch((e) => {
        res.status(400).send(e);
    });
})

/**
 * GET /users/me/access-token
 * Cel: Wygenerowanie i zwrocenie tokenu dostepu
 */
 app.get('/users/me/access-token', verifySession, (req, res) => {
    //uzytkownik ma autoryzacje a my posiadamy jego id i cialo uzytkownika
    req.userObject.generateAccessAuthToken().then((accessToken) => {
        res.header('x-access-token', accessToken).send({ accessToken });
    }).catch((e) => {
        res.status(400).send(e);
    });
})

/* Metody pomocniczne */
let deleteTasksFromList = (_listId) =>{
    Task.deleteMany({
        _listId
    }).then(() =>{
        console.log("Zadania z " + _listId + " zostały usunięte");
    });
}

app.listen(3000, () => {
    console.log("Serwer jest na porcie 3000");
})