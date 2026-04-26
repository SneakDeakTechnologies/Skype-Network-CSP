import chalk from 'chalk';

function print(message) {
    console.log(chalk.bold.cyan(message));
};

function error(message) {
    console.log(chalk.bold.red(message));
};

export default {
    print,
    error
};