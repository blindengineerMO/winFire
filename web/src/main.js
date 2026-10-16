import {createApp} from 'vue'
import {createPinia} from 'pinia'
import {createRouter,createWebHistory} from 'vue-router'
import App from './App.vue'
const Dashboard=()=>import('./views/Dashboard.vue')
const Inventory=()=>import('./views/Inventory.vue')
const Directory=()=>import('./views/Directory.vue')
const Policies=()=>import('./views/Policies.vue')
const Reports=()=>import('./views/Reports.vue')
const Logs=()=>import('./views/Logs.vue')
const Identity=()=>import('./views/Identity.vue')
const MfaPrompt=()=>import('./views/MfaPrompt.vue')
const Administration=()=>import('./views/Administration.vue')
const Login=()=>import('./views/Login.vue')
const AcceptInvite=()=>import('./views/AcceptInvite.vue')
const VerifyEmail=()=>import('./views/VerifyEmail.vue')
const EnrollAuthenticator=()=>import('./views/EnrollAuthenticator.vue')
const Tools=()=>import('./views/Tools.vue')
const Internet=()=>import('./views/Internet.vue')
const AiUsage=()=>import('./views/AiUsage.vue')
const Mapping=()=>import('./views/Mapping.vue')
import {session} from './services/api.js'
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
  {path:'/mapping',component:Mapping},
  {path:'/ai-usage',component:AiUsage},
  {path:'/identity',component:Identity},
  {path:'/admin',component:Administration}
]
const router=createRouter({history:createWebHistory(),routes})
router.beforeEach(to=>!to.meta.public&&!session.token?{path:'/login',query:{next:to.fullPath}}:to.path==='/login'&&session.token?'/':true)
router.beforeEach(to=>to.path==='/admin'&&to.query.tab==='notifications'&&to.query.notificationTab==='ddos'?{path:'/logs',query:{tab:'ddos'},replace:true}:true)
createApp(App).use(createPinia()).use(router).mount('#app')
