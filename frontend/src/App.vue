<template>
  <div id="app">
    <CVEList />
  </div>
</template>

<script>
import { defineComponent } from 'vue';
import CVEList from './components/CVEList.vue';

export default defineComponent({
  name: 'App',
  components: {
    CVEList
  }
});
</script>

<style>
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
  margin-top: 60px;
}
</style>