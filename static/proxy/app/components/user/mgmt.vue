<template>
<div>

  <h2>User Admin</h2>

  <div v-if="adding_user">

    <b-btn variant="info"
           v-on:click="cancelAddUser()"
    >Cancel</b-btn>


    <b-jumbotron
               header="Add user"
               lead="Enter user details:" >
      <div class="col-6">

        <b-input-group>
          <div class="input-group-prepend w-25">
            <span class="input-group-text w-100" id="id">User email</span>
          </div>
          <b-form-input
                        type="text"
                        v-model="newuser.email"
                        placeholder="Enter user email adress (login)"
                        v-on:keyup.enter.native="addUser()"
                        :state="state_newuser_email"
          ></b-form-input>

          <b-form-invalid-feedback>
            Valid email address is required for login name
          </b-form-invalid-feedback>

        </b-input-group>

        <b-input-group>
          <div class="input-group-prepend w-25">
            <span class="input-group-text w-100" id="id">User password</span>
          </div>
          <b-form-input
                        type="password"
                        v-model="newuser.passwd1"
                        placeholder="Enter user password"
                        v-on:keyup.enter.native="addUser()"
          ></b-form-input>
        </b-input-group>

        <b-input-group>
          <div class="input-group-prepend w-25">
            <span class="input-group-text w-100" id="id">User password verify</span>
          </div>
          <b-form-input
                        type="password"
                        v-model="newuser.passwd2"
                        placeholder="Enter user password"
                        v-on:keyup.enter.native="addUser()"
                        :state="state_newuser_passwd2"
          ></b-form-input>

          <b-form-invalid-feedback>
            Password does not match
          </b-form-invalid-feedback>

        </b-input-group>

        <b-input-group>
          <div class="input-group-prepend w-25">
            <span class="input-group-text w-100" id="id">First name</span>
          </div>
          <b-form-input
                        type="text"
                        v-model="newuser.firstname"
                        placeholder="Enter first name"
                        v-on:keyup.enter.native="addUser()"
          ></b-form-input>
        </b-input-group>

        <b-input-group>
          <div class="input-group-prepend w-25">
            <span class="input-group-text w-100" id="id">Last name</span>
          </div>
          <b-form-input
                        type="text"
                        v-model="newuser.lastname"
                        placeholder="Enter last name"
                        v-on:keyup.enter.native="addUser()"
          ></b-form-input>
        </b-input-group>

        <b-input-group>
          <div class="input-group-prepend w-25">
            <span class="input-group-text w-100" id="id">User description</span>
          </div>
          <b-form-input
                        type="text"
                        v-model="newuser.description"
                        placeholder="Enter user description"
                        v-on:keyup.enter.native="addUser()"
          ></b-form-input>

          <b-input-group-append>
            <b-btn variant="success"
                   v-on:click="addUser()"
            >Add user</b-btn>
          </b-input-group-append>
        </b-input-group>

      </div>

    </b-jumbotron>

  </div>

  <div v-if="!adding_user">

    <b-btn variant="info"
           v-on:click="showAddUser()"
    >Add user</b-btn>

    <b-input-group>
      <div class="input-group-prepend w-25">
        <span class="input-group-text w-100" id="user_filter">Search user</span>
      </div>
      <b-form-input
                    type="text"
                    v-model="user_filter"
                    placeholder="Enter part of username"
                    v-on:keyup.enter.native="getUsers()"
      ></b-form-input>
      <b-input-group-append>
        <b-btn variant="info"
               v-on:click="getUsers()"
        >Search</b-btn>
      </b-input-group-append>

    </b-input-group>

  <b-alert class="col-6" :show="10" v-if="tokenExpiresIn < 3600"> Access token will expire in {{ tokenExpiresIn }} seconds </b-alert>

  <error-axios
    v-bind:err_resp="err_resp"
  >
  </error-axios>

  <div v-if="!adding_user">

    <div v-if="loading">
      <b-alert class="col-6" show > Searching ... </b-alert>
    </div>

    <div v-else-if="!loading && users && users.length > 0">
      <user
        v-for="(name, index) in users"
        v-bind:key="index"
        v-bind:name="name"
        v-bind:creds="creds"
        v-bind:controller="controller"
        v-bind:user_regex="user_regex"
      >
      </user>
    </div>

    <div v-if="!loading && users && users.length == 0">
        <b-alert class="col-6" show> No users found ... </b-alert>
    </div>
  </div>

</div>
</template>

<script>

module.exports = {
  data () {
    return {
      adding_user: false,
      info: null,
      loading: false,
      err_resp: null,
      alert_msg: "",
      users: [],
      newuser: null,
      user_filter: ""
    }
  },
  props: ["controller", "creds"],
  computed: {
    // Number of seconds the token will expire in, if expire time is set
    tokenExpiresIn() {
      if (!this.creds.token || this.creds.token.expires == 0) {
        return null
      }
      return this.creds.token.expires - Math.floor(Date.now() / 1000)
    },
    user_regex () {
      if (!this.user_filter) {
        return null
      }
      return new RegExp(this.user_filter, 'ig')
    },
    state_newuser_email () {
      re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
    return re.test(String(this.newuser.email).toLowerCase())
    },
    state_newuser_passwd2 () {
      if (this.newuser.passwd1 != this.newuser.passwd2) {
          return false
      }
      if (this.newuser.passwd1) {
        return true
      }
    }
  },
  mounted () {
    this.getUsers()
  },
  methods: {
    clear() {
      this.err_resp = null
      this.alert_msg = ""
    },
    showAddUser() {
      this.clear()
      this.newuser = {
        name: "",
        email: "", // should usually be the same as name
        plainpasswd: "",
        passwd1: "",
        passwd2: "",
        firstname: "",
        lastname: "",
        description: "",
        roles: []
      }
      this.adding_user = true
    },
    cancelAddUser() {
      this.adding_user = false
    },
    addUser() {
      this.clear()
      this.newuser.name = this.newuser.email
      if (this.newuser.passwd1) {
        this.newuser.plainpasswd = this.newuser.passwd1
      }
      Vue.delete(this.newuser, "passwd1")
      Vue.delete(this.newuser, "passwd2")
      axios
        .post(this.$restApi + this.controller + "/rpc/create-user", {
          newuser: this.newuser}, {
          headers: {'X-ZTC-Token': this.creds.token.id }
        }).then(response => {
          this.users.push(response.data.name)
        }).catch(error => {
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
        .finally(() => this.adding_user = false)
    },
    getUsers (event) {
      this.clear()
      this.loading = true
      axios
        .post(this.$restApi + this.controller + "/rpc/get-usernames", {}, {
          headers: {'X-ZTC-Token': this.creds.token.id }
        }).then(response => {
          this.users = response.data
        }).catch(error => {
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
