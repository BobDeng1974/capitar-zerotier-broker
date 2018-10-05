<template>
<div>

  <b-jumbotron header="Controller" lead="Query networks" >
    <b-input-group prepend="Controller Name">
      <b-form-input class="col-4"
                    type="text"
                    v-model="controller"
                    placeholder="Enter controller name"
                    v-on:keyup.enter.native="getNetworks"
      ></b-form-input>
      <b-input-group-append>
        <b-btn variant="success"
               v-on:click="getNetworks"
        >Get Networks</b-btn>
        <b-btn variant="info">Get Status</b-btn>
      </b-input-group-append>
    </b-input-group>
  </b-jumbotron>

  <section v-if="errored">
    <p>We're sorry, we're not able to retrieve this
       information at the moment, please try back later</p>
  </section>

  <section v-else>
    <div v-if="loading"> Loading... </div>

    <div v-else-if="networks">

      <network
        v-for="nwid, index in networks"
        v-bind:id="nwid"
        v-bind:controller="controller"
      >
      </network>

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
      controller: "",
      networks: null
    }
  },
  props: ["controller"],
  methods: {
    getNetworks (event) {
      if (this.controller == null) {
        alert("Please enter name")
        return
      }
      this.loading = true
      axios
        .get("/api/1.0/proxy/" + this.controller + "/network")
        .then(response => {
          this.networks = response.data
        })
        .catch(error => {
          console.log(error)
          this.errored = true
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
