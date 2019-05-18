<template>
<div>

<navbar
  :key="load_user_inc"
  v-bind:controller="controller"
  v-bind:creds="creds"
  v-on:logout="logout"
  v-on:useradmin="useradmin"
  v-on:deviceadmin="deviceadmin"
  v-on:networkadmin="networkadmin"
></navbar>

<b-jumbotron v-if="!creds.token || !creds.token.id"
             :header="$appName"
             lead="Enter Credentials to Login:" >
  <div class="col-6">

    <b-input-group>
      <div class="input-group-prepend w-25">
        <span class="input-group-text w-100" id="controller-name">
          Controller Name
        </span>
      </div>

      <b-form-input 
                    type="text"
                    v-model="controller"
                    placeholder="Enter controller name"
                    v-on:keyup.enter.native="getControllerStatus"
      ></b-form-input>
      <b-input-group-append>
        <b-btn variant="info"
               v-on:click="getControllerStatus"
        >Check Controller Status</b-btn>
      </b-input-group-append>
    </b-input-group>

    <b-input-group>
      <div class="input-group-prepend w-25">
        <span class="input-group-text w-100" id="username">Username</span>
      </div>
      <b-form-input 
                    type="text"
                    v-model="creds.username"
                    placeholder="Enter username"
                    v-on:keyup.enter.native="login"
      ></b-form-input>
    </b-input-group>

    <b-input-group>
      <div class="input-group-prepend w-25">
        <span class="input-group-text w-100" id="basic-addon3">Password</span>
      </div>
      <b-form-input 
                    type="password"
                    v-model="creds.password"
                    placeholder="Enter password"
                    v-on:keyup.enter.native="login"
      ></b-form-input>
    </b-input-group>


    <b-input-group>
      <div class="input-group-prepend w-25">
        <span class="input-group-text w-100" id="oath-token">Access Token</span>
      </div>
      <b-form-input 
                    type="text"
                    v-model="creds.oath"
                    placeholder="Enter One Time Access Token if required"
                    v-on:keyup.enter.native="login"
      ></b-form-input>
      <b-input-group-append>
        <b-btn variant="success"
               //v-on:click="login"
        >Login</b-btn>
      </b-input-group-append>
    </b-input-group>

    <b-list-group v-if="controller_status" >
      <b-list-group-item v-if="controller_status.central" >
            Zerotier Central</b-list-group-item>
      <b-list-group-item v-if="controller_status.controller" >
            Zerotier One
      </b-list-group-item>
      <b-list-group-item>
            Version: {{ controller_status.version }}
      </b-list-group-item>
      <b-list-group-item>
            Description: {{ controller_status.description }}
      </b-list-group-item>
    </b-list-group>
  </div>

  <b-alert class="col-6" :show="show_alert_msg"> {{ alert_msg }} </b-alert>

  <error-axios
    v-bind:err_resp="err_resp"
  >
  </error-axios>

</b-jumbotron>

<user-mgmt v-if="!loading && selected_useradmin && creds && creds.token"
  v-bind:controller="controller"
  v-bind:creds="creds"
  v-on:load_user="load_user"
></user-mgmt>

<controller v-if="!loading && selected_networkadmin && creds && creds.token"
  v-bind:controller="controller"
  v-bind:creds="creds"
  v-on:load_user="load_user"
></controller>

<my-devices v-if="!loading && selected_deviceadmin && creds && creds.token"
  v-bind:controller="controller"
  v-bind:creds="creds"
  v-on:load_user="load_user"
></my-devices>

</div>
</template>

<script>

module.exports = {
  data () {
    return {
      load_user_inc: 0,
      info: null,
      loading: false,
      err_resp: null,
      alert_msg: "",
      controller: "personal",
      controller_status: null,
      selected: "",
      networks: null,
      nw_filter: "",
      creds: { username: "", password: "", oath: "", token: null, ready: false },
    }
  },
  props: [],
  computed: {
    show_alert_msg() {
      if (this.alert_msg) {
        return true
      }
      return false
    },
    // Number of seconds the token will expire in, if expire time is set
    tokenExpiresIn() {
      if (!this.creds.token || this.creds.token.expires == 0) {
        return null
      }
      return this.creds.token.expires - Math.floor(Date.now() / 1000)
    },
    selected_useradmin() {
      if (this.selected == "useradmin") {
        return true
      }
    },
    selected_deviceadmin() {
      if (this.selected == "deviceadmin") {
        return true
      }
    },
    selected_networkadmin() {
      if (this.selected == "networkadmin") {
        return true
      }
    }
  },
  methods: {
    logout() {
      this.clear()
      axios
        .delete(this.$restApi + this.controller + "/token/" + this.creds.token.id, {
        headers: {'X-ZTC-Token': this.creds.token.id }
        })
        .then(response => {
          //this.creds = { username: "", password: "", oath: "", token: ""}
        })
        .catch(error => {
          if ((error.response) && error.response.status ) {
            this.err_resp = error.response
          }
          else {
            console.log("undefined error: ", error)
          }
        })
        .finally(() => this.loading = false)
      // Immediately delete token, regardless of result of delete token request
      this.creds = { username: "", password: "", oath: "", token: ""}
    },
    clear() {
      this.controller_status = null
      this.err_resp = null
      this.alert_msg = ""
    },
    useradmin() {
      this.selected = "useradmin"
    },
    deviceadmin() {
      this.selected = "deviceadmin"
    },
    networkadmin() {
      this.selected = "networkadmin"
    },
    load_user() {
      this.loading = true
      axios
        .post(this.$restApi + this.controller + "/rpc/get-own-user", {}, {
          headers: {'X-ZTC-Token': this.creds.token.id }
        })
        .then(response => {
          this.creds.user = response.data
          this.creds.ready = true
          this.load_user_inc += 1
          switch (this.selected) {
            case "useradmin":
              this.useradmin()
              break
            case "deviceadmin":
              this.deviceadmin()
              break
            case "networkadmin":
              this.networkadmin()
              break
            default:
              this.deviceadmin()
          }
        })
        .catch(error => {
          if ((error.response) && error.response.status ) {
            this.err_resp = error.response
          }
          else {
            console.log("undefined error: ", error)
          }
        })
        .finally(() => this.loading = false)
    },
    login (event) {
      if ((this.controller == null) || (this.controller == "")) {
        this.alert_msg = "Please enter controller name"
        return
      }
      if ((this.creds.username == "")) {
        this.alert_msg = "Please enter username"
        return
      }
      if ((this.creds.password == "")) {
        this.alert_msg = "Please enter password"
        return
      }
      this.clear()
      axios
        .post(this.$restApi + this.controller + "/token", {
            expires: this.$cfg.tokenLifeTime + Math.floor(Date.now() / 1000)
          }, {
          auth: {
            username: this.creds.username,
            password: this.creds.password
          },
        }).then(response => {
          this.creds.token = response.data
          this.creds.password = ''
        })
        .catch(error => {
          if ((error.response) && (error.response.status == 404)) {
            this.alert_msg = "No such controller found"
          }
          if ((error.response) && error.response.status ) {
            this.err_resp = error.response
          }
          else {
            console.log("undefined error: ", error)
          }
        })
        .finally(() => {
          this.loading = false
          this.load_user()
        })
    },
    getControllerStatus (event) {
      if ((this.controller == null) || (this.controller == "")) {
        this.alert_msg = "Please enter controller name"
        return
      }
      this.clear()
      axios
        .get(this.$restApi + this.controller + "/status")
        .then(response => {
          this.controller_status = response.data
        })
        .catch(error => {
          if ((error.response) && (error.response.status == 404)) {
            this.alert_msg = "No such controller found"
          }
          if ((error.response) && error.response.status ) {
            this.err_resp = error.response
          }
          else {
            console.log("undefined error: ", error)
          }
        })
        .finally(() => this.loading = false)
    }
  }
}

</script>

<style>
.jumbotron {
    //background-color: #ffe;
}
.display-3 {
    font-size: 2.5rem;
    font-weight: 300;
    line-height: 1.2;
    }
}
</style>
