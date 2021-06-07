// Podtrzymanie polaczenia z baza danych MongoDB

const mongoose = require('mongoose');

mongoose.Promise = global.Promise;
mongoose.connect('mongodb://localhost:27017/TaskManager', { useNewUrlParser: true }).then(() => {
    console.log("Polaczenie do MongoDB zakonczone powodzeniem :)");
}).catch((e) => {
    console.log("Blad w trakcie proby polaczenia do MongoDB");
    console.log(e);
});

// Aby zapobiec ostrzezeniom ze strony MongoDB
mongoose.set('useCreateIndex', true);
mongoose.set('useFindAndModify', false);


module.exports = {
    mongoose
};