<template>

<div v-if="show_network">

  <section v-if="errored">
    <p>We're sorry, we're not able to retrieve this
       information at the moment, please try back later</p>
  </section>

  <section v-else>
    <div v-if="loading"> <!-- Loading... --> </div>

    <div v-else>

      <b-jumbotron :header="networkName" :lead="networkId" >
       <p>For more information visit website</p>
       <b-btn variant="primary" href="#">More Info</b-btn>

        <b-card bg-variant="secondary"
              :header="networkName"
              text-variant="white"
              class="text-center">
          <p class="card-text"> {{ network.id }} </p>
          <b-button href="#" variant="primary">Go somewhere</b-button>
        </b-card>
      </b-jumbotron>

    </div>

  </section>

</div>

</template>

<script>

module.exports = {

  computed: {
    networkName() {
      return this.network.name;
    },
    networkId() {
      return this.network.id;
    },
    show_network() {
      return true
      /*
      if (!this.nw_filter) {
        return true
      }
      if (this.network.name.match(/this.nw_filter/) {
        return true
      }
      if (this.network.id.match(/this.nw_filter/) {
        return true
      }*/
    }
  },
  data () {
    return {
      show_network: true,
      info: null,
      loading: true,
      errored: false,
      network: null
    }
  },
  props: ["id", "index", "networks", "controller", "creds", "nw_filter"],
  mounted () {
    axios
      .get("/api/1.0/proxy/" + this.controller + "/network/" + this.id)
      .then(response => {
        this.network = response.data
      })
      .catch(error => {
        console.log(error)
        this.errored = true
      })
      .finally(() => this.loading = false)
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
