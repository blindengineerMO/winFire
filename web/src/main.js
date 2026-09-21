import {createApp} from 'vue'
import {createPinia} from 'pinia'
import {createRouter,createWebHistory} from 'vue-router'
import App from './App.vue'
import Dashboard from './views/Dashboard.vue'
import Inventory from './views/Inventory.vue'
import Directory from './views/Directory.vue'
import Policies from './views/Policies.vue'
import Reports from './views/Reports.vue'
import Logs from './views/Logs.vue'
import Identity from './views/Identity.vue'
import MfaPrompt from './views/MfaPrompt.vue'
import Administration from './views/Administration.vue'
import Login from './views/Login.vue'
import AcceptInvite from './views/AcceptInvite.vue'
import VerifyEmail from './views/VerifyEmail.vue'
import EnrollAuthenticator from './views/EnrollAuthenticator.vue'
import Tools from './views/Tools.vue'
import Internet from './views/Internet.vue'
import {session} from './lib/api.js'
import '@mdi/font/css/materialdesignicons.css'
import './styles.scss'
import './enterprise.scss'
import './notifications.scss'

const routes=[
  {path:'/login',component:Login,meta:{public:true}},
  {path:'/accept-invite',component:AcceptInvite,meta:{public:true}},
  {path:'/verify-email',component:VerifyEmail,meta:{public:true}},
  {path:'/enroll-authenticator',component:EnrollAuthenticator,meta:{public:true}},
  {path:'/tools',component:Tools,meta:{public:true}},
  {path:'/mfa/callback',component:MfaPrompt,meta:{public:true}},
  {path:'/mfa/:promptId',component:MfaPrompt,meta:{public:true}},
  {path:'/',component:Dashboard},
  {path:'/inventory',component:Inventory},
  {path:'/directory',component:Directory},
  {path:'/policies',component:Policies},
  {path:'/reports',component:Reports},
  {path:'/logs',component:Logs},
  {path:'/internet',component:Internet},
  {path:'/identity',component:Identity},
  {path:'/admin',component:Administration}
]
const router=createRouter({history:createWebHistory(),routes})
router.beforeEach(to=>!to.meta.public&&!session.token?{path:'/login',query:{next:to.fullPath}}:to.path==='/login'&&session.token?'/':true)
createApp(App).use(createPinia()).use(router).mount('#app')
