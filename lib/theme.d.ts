declare const theme: {
    colors: {
        background: string[];
        text: string;
        primary: string;
        secondary: string;
        accent: string;
        disabled: string;
    };
    animationSpeed: number;
};
export type Theme = typeof theme;
export default theme;
