const express = require('express')
const app = express()
var request = require('request')
const crypto = require('crypto')
const env = require('dotenv')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
var jwt = require('jsonwebtoken')
const res = require('express/lib/response')
const { json } = require('body-parser')
const { execute, enforce} = require('./casbinHelper')
let state_DB = []

const methodToAction = {
    GET: 'read',
    POST: 'write'
}

const port = 3001
env.config()

// system variables where RP credentials are stored
const CLIENT_ID = process.env.CLIENT_ID
const CLIENT_SECRET = process.env.CLIENT_SECRET
const CALLBACK = 'callback'

app.use(cookieParser())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
 
const login = (req, resp) => {
    let state = crypto.randomUUID()
    state_DB.push({state})
    resp.redirect(302,
        'https://accounts.google.com/o/oauth2/v2/auth?'
        + 'client_id='+ CLIENT_ID +'&'
        + 'scope=openid%20email%20https://www.googleapis.com/auth/tasks&'
        + `state=${state}&`
        + 'response_type=code&'
        + 'redirect_uri=http://localhost:3001/' + CALLBACK
    )
}

const callback = (req, resp) => {
    if(verifyState(req.query.state)){
        request
            .post(
                { 
                    url: 'https://www.googleapis.com/oauth2/v3/token',
                    // body parameters
                    form: {
                        code: req.query.code,
                        client_id: CLIENT_ID,
                        client_secret: CLIENT_SECRET,
                        redirect_uri: 'http://localhost:3001/'+CALLBACK,
                        grant_type: 'authorization_code'
                    }
                }, 
                function(err, httpResponse, body){
                    if(err){
                        resp.redirect('/error')
                    }
                    var json_response = JSON.parse(body);
                    var jwt_payload = jwt.decode(json_response.id_token)
                    
                    //resp.cookie("AuthCookie",json_response.access_token,{maxAge:3600,httpOnly:true})
                    const access_token = json_response.access_token
                    request
                        .get(
                            {
                                url: 'https://tasks.googleapis.com/tasks/v1/users/@me/lists',
                                headers:{
                                    Authorization: `Bearer ${json_response.access_token}`
                                }
                            },
                            function(err, httpResponse, body) { 
                                if(err){
                                    resp.redirect('/error')
                                }

                                var json_response = JSON.parse(body);
                                
                                state_DB = state_DB.map(index => {
                                    if(index.state == req.query.state) {
                                        index.token = access_token
                                        index.email = jwt_payload.email
                                        resp.cookie("AuthCookie",index.state)
                                    }
                                    return index
                                })
                                //resp.cookie("AuthCookie",access_token)
                                let listHtml = json_response.items.map(item => `<div><a href = '/list/${item.id}'>${item.title}</a></div>`).join("<br></br>")
                                resp.send(listHtml)
                            }
                        )
                }
            );
    }else{
        resp.redirect('/error')
    }
}

const getTaskList = (req, resp) => {
    const token = getToken(req.cookies.AuthCookie)
    request
        .get(
            {
                url: `https://tasks.googleapis.com/tasks/v1/lists/${req.params.id}/tasks`,
                headers:{
                    Authorization: `Bearer ${token}`
                }
            },
            function(err, httpResponse, body){
                if(err){
                    resp.redirect('/error')
                }

                var json_response = JSON.parse(body);
                let listHtml = json_response.items.map(item => `<div><h1 href = '/task/${item.id}'>${item.title}</h1><p>${item.notes ? item.notes : "There's no notes for this task"}</p></div>`).join("<br></br>")
                listHtml += "<br></br><h1>Create a new task</h1><form method= 'post'>" + 
                "<label for='title'>Title:</label><br>" +
                "<input type='text' id='title' name='title' value=''><br>" +
                "<label for='notes'>Notes:</label><br>" +
                "<input type='text' id='notes' name='notes' value=''><br><br>" +
                "<input type='submit' value='Submit'>" +
                "</form>"
                resp.send(listHtml)
            }
        )
}

const postTask = (req,resp) => {
    const token = getToken(req.cookies.AuthCookie)
    request
        .post(
            {
                url: `https://tasks.googleapis.com/tasks/v1/lists/${req.params.id}/tasks`,
                headers:{
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body:JSON.stringify({ title: req.body.title, notes: req.body.notes })
            },
            function(err, httpResponse, body){
                if(err){
                    resp.redirect('/error')
                }
                resp.redirect(`/list/${req.params.id}`)
            }
        )
}

const error = (req, resp) => {
    resp.send("<p>Something went wrong. Try again. </p><a href='/login'>Login</a>")
}

const unauthorized = (req, resp) => {
    resp.send(`<p>You are not allowed to access this feature.</p> <img src="https://st.depositphotos.com/3332767/4585/i/950/depositphotos_45854107-stock-photo-man-holding-stop-sign.jpg" width="1000" height="600">`)
}

const authMiddleware = (req, resp, next) => {
    if (!req.cookies.AuthCookie || !getToken(req.cookies.AuthCookie)) {
        resp.redirect('/login')
    } else {
        next()
    }
}

const rbacMiddleware = (req, resp, next) => {
    const sub = getEmail(req.cookies.AuthCookie)
    const { path: obj } = req;
    const act = methodToAction[req.method];
    enforce(sub, obj, act).then(decision => {
        execute(decision)
        if(decision.res) next()
        else resp.redirect('/unauthorized')
    })
}

const getToken = (state) => {
    let token = state_DB.filter(index => {
        return index.state == state
    })[0].token
    return token
}

const getEmail = (state) => {
    let email = state_DB.filter(index => {
        return index.state == state
    })[0].email
    return email
}

const verifyState = (state) => {
    return state_DB.filter(index => index.state == state)[0]
}


app.get('/', (req, resp) => {
    resp.send('<a href="/login">Use Google Account</a>')
})

app.get('/login', login)

app.get('/' + CALLBACK, callback)

app.get('/list/:id', authMiddleware, rbacMiddleware, getTaskList)

app.post('/list/:id', authMiddleware, rbacMiddleware, postTask)

app.get('/error', error)

app.get('/unauthorized', unauthorized)

app.listen(port, (err) => {
    if (err) {
        return console.log('something bad happened', err)
    }
    console.log(`server is listening on ${port}`)
})