<template>
<div>

<b-jumbotron header="Controller" lead="Query networks" >
  <div class="col-6">
    <b-input-group prepend="Controller Name">
      <b-form-input 
                    type="text"
                    v-model="controller"
                    placeholder="Enter controller name"
                    v-on:keyup.enter.native="getNetworks"
      ></b-form-input>
      <b-input-group-append>
        <b-btn variant="success"
               v-on:click="getNetworks"
        >Get Networks</b-btn>
        <b-btn variant="info"
               v-on:click="getControllerStatus"
        >Get Status</b-btn>
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
  <b-alert class="col-6" :show="need_controller_name">Please enter controller name</b-alert>
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
    <div v-else-if="networks && networks.length > 0">

      <network
        v-for="nwid, index in networks"
        v-bind:id="nwid"
        v-bind:controller="controller"
      >
      </network>

    </div>

    <div v-else-if="no_such_controller">
        <b-alert class="col-6" show> No such controller found ... </b-alert>
    </div>
    <div v-else-if="networks">
        <b-alert class="col-6" show> No networks found ... </b-alert>
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
      no_such_controller: false,
      controller_status: null,
      controller: "",
      networks: null
    }
  },
  props: ["controller"],
  methods: {
    clear() {
      this.need_controller_name = false
      this.no_such_controller = false
      controller_status: null,
      this.error = null
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
