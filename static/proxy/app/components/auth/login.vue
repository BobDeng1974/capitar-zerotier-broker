<template>
<div>

<b-jumbotron v-if="!creds.token || !creds.token.id"
             header="ZeroTier Network Controller"
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
    </b-list-group>
  </div>
  <b-alert class="col-6" :show="need_controller_name"> Please enter controller name </b-alert>
  <b-alert class="col-6" :show="need_username"> Please enter username </b-alert>
  <b-alert class="col-6" :show="need_password"> Please enter password </b-alert>
  <b-alert class="col-6" :show="need_oath"> Please enter access token </b-alert>
  <b-alert class="col-6" :show="no_such_controller"> No such controller found </b-alert>
</b-jumbotron>

<b-btn v-if="controller && creds && creds.token" variant="warning"
    v-on:click="logout"
>Logout</b-btn>


<controller v-if="controller && creds && creds.token && (controller != 'libvirt-lenojbo')"
  v-bind:controller="controller"
  v-bind:creds="creds"
></controller>

<controller-libvirt
  v-if="controller && creds && creds.token && (controller == 'libvirt-lenojbo')"
  v-bind:controller="controller"
  v-bind:creds="creds"
></controller-libvirt>

</div>
</template>

<script>

module.exports = {
  data () {
    return {
      info: null,
      loading: false,
      errored: false,
      error: null,
      need_controller_name: false,
      need_username: false,
      need_password: false,
      need_oath: false,
      no_such_controller: false,
      controller: null,
      controller_status: null,
      networks: null,
      nw_filter: "",
      creds: { username: "", password: "", oath: "", token: null },
    }
  },
  props: [],
  computed: {
    // Number of seconds the token will expire in, if expire time is set
    tokenExpiresIn() {
      if (!this.creds.token || this.creds.token.expires == 0) {
        return null
      }
      return this.creds.token.expires - Math.floor(Date.now() / 1000)
    }
  },
  methods: {
    logout() {
      axios
        .delete(this.$restApi + this.controller + "/token/" + this.creds.token.id, {
        headers: {'X-ZTC-Token': this.creds.token.id }
        })
        .then(response => {
          this.creds = { username: "", password: "", oath: "", token: ""}
        })
        .catch(error => {
          if ((error.response) && (error.response.status == 404)) {
            // Perhaps the controller has been pruned, or the token does not exist
            // this.no_such_controller = true
            console.log(error)
            this.errored = true
          }
          else {
            console.log(error)
            this.errored = true
          }
        })
        .finally(() => this.loading = false)
    },
    clear() {
      this.need_controller_name = false
      this.need_username = false
      this.need_password = false
      this.need_oath = false
      this.no_such_controller = false
      controller_status: null,
      this.error = null
    },
    login (event) {
      if ((this.controller == null) || (this.controller == "")) {
        this.need_controller_name = true
        return
      }
      if ((this.creds.username == "")) {
        this.need_username = true
        return
      }
      if ((this.creds.password == "")) {
        this.need_password = true
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
          //headers: { 'Authorization': + 'xx'}
          //headers: { 'X-ZTC-Token:': + 'xx' }
        }).then(response => {
          this.creds.token = response.data
          this.creds.password = ''
        })
        .catch(error => {
          if ((error.response) && (error.response.status == 404)) {
            this.no_such_controller = true
          }
          else {
            console.log(error)
            this.errored = true
          }
        })
        .finally(() => this.loading = false)
    },
    getControllerStatus (event) {
      if ((this.controller == null) || (this.controller == "")) {
        this.need_controller_name = true
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
            this.no_such_controller = true
          }
          else {
            console.log(error)
            this.errored = true
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
