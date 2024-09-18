<template>
  <div>
    <CVETable />
  </div>
</template>

<script>
import CVETable from '@/components/CVETable.vue';

export default {
  name: 'HomeView', // Change the component name to be multi-word
  components: {
    CVETable
  }
};
</script>

<style>
/* existing style code */
</style>