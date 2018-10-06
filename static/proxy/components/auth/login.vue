<template>
<div>

<b-jumbotron v-if="!creds.token && !creds.token.id"
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


<b-jumbotron v-if="creds.token && creds.token.id"
             header="ZeroTier Network Controller"
             :lead=controller >
  <div class="col-6">

    <b-input-group>
      <div class="input-group-prepend w-25">
        <span class="input-group-text w-100" id="nw_filter">Search network</span>
      </div>
      <b-form-input 
                    type="text"
                    v-model="nw_filter"
                    placeholder="Enter part of ID or name"
                    v-on:keyup.enter.native="show_networks=true"
      ></b-form-input>
      <b-input-group-append>
        <b-btn variant="success"
               v-on:click="show_networks=true"
        >Search</b-btn>
        <b-btn variant="warning"
               v-on:click="logout"
        >Logout</b-btn>
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


  <section v-if="errored">
    <i v-if="error"> {{ error }} </i>
    <p>We're sorry, we're not able to retrieve this
       information at the moment, please try back later</p>
  </section>

  <section v-else>
    <div v-if="loading">
      <b-alert class="col-6" show > Searching ... </b-alert>
    </div>
    <div v-else-if="controller && creds.token">

      <controller
        v-bind:creds="creds"
        v-bind:controller="controller"
        v-bind:nw_filter="nw_filter"
      >
      </controller>

    </div>

  </section>

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
      controller_status: null,
      controller: "",
      networks: null,
      nw_filter: "",
      creds: { username: "", password: "", oath: "", token: "" },
    }
  },
  props: ["controller"],
  methods: {
    logout() {
      this.creds = { username: "", password: "", oath: "", token: ""}
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
        .post("/api/1.0/proxy/" + this.controller + "/token", {
            expires: 3600*8 + Math.floor(Date.now() / 1000)
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
        .get("/api/1.0/proxy/" + this.controller + "/status")
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
    },
    getNetworks (event) {
      if ((this.controller == null) || (this.controller == "")) {
        this.need_controller_name = true
        return
      }
      this.clear()
      this.loading = true
      axios
        .get("/api/1.0/proxy/" + this.controller + "/network")
        .then(response => {
          this.networks = response.data
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
