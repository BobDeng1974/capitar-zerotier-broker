<template>
<div>

  <div>
    <b-btn variant="success"
           v-on:click="newUser()"
    >Add new user</b-btn>

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

  <div v-if="loading">
    <b-alert class="col-6" show > Searching ... </b-alert>
  </div>

  <div v-else-if="users && users.length > 0">
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

  <div v-else-if="users">
      <b-alert class="col-6" show> No users found ... </b-alert>
  </div>

</div>
</template>

<script>

module.exports = {
  data () {
    return {
      info: null,
      loading: true,
      err_resp: null,
      alert_msg: "",
      user: []
    }
  },
  props: ["controller", "creds", "user_filter"],
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
      return new RegExp(this.user_filter, 'g')
    }
  },
  mounted () {
    this.user_filter = this.user_filter
    this.getUsers()
  },
  methods: {
    clear() {
      this.loading = true
      this.err_resp = null
      this.alert_msg = ""
    },
    getUsers (event) {
      this.clear()
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
